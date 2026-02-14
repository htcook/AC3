/**
 * Post-Engagement Report Generator
 * 
 * Compiles operation results, detection rates, rule validation scores,
 * and MITRE ATT&CK mapping into a structured report.
 * 
 * Branded: AceofCloud | Ace C3 Platform
 */

import { invokeLLM } from "../_core/llm";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface ReportInput {
  operationId: string;
  operationData: any;
  coverageData?: any;
  threatActors?: Array<{ name: string; techniques: number; type: string }>;
  clientName?: string;
  engagementType?: string;
  customNotes?: string;
}

export interface ReportSection {
  title: string;
  content: string;
}

export interface ReportData {
  metadata: {
    title: string;
    subtitle: string;
    author: string;
    company: string;
    website: string;
    date: string;
    clientName: string;
    engagementType: string;
    operationId: string;
    operationName: string;
    classification: string;
  };
  executiveSummary: string;
  scopeAndMethodology: string;
  operationTimeline: Array<{
    time: string;
    event: string;
    status: string;
    techniqueId: string;
  }>;
  attackChainResults: Array<{
    techniqueId: string;
    techniqueName: string;
    tactic: string;
    status: string;
    stepsExecuted: number;
    stepsSucceeded: number;
    detectionStatus: string;
  }>;
  metrics: {
    totalSteps: number;
    completedSteps: number;
    successRate: number;
    detectionRate: number;
    techniquesAttempted: number;
    techniquesSucceeded: number;
    tacticsCovered: number;
    avgConfidence: number;
  };
  detectionCoverage: {
    totalTechniques: number;
    fullCoverage: number;
    partialCoverage: number;
    noCoverage: number;
    coveragePercentage: number;
    gaps: Array<{ techniqueId: string; techniqueName: string; tactic: string; recommendation: string }>;
  };
  ruleValidation: {
    totalRules: number;
    validRules: number;
    avgEffectiveness: number;
    rulesByType: Record<string, number>;
    topIssues: string[];
  };
  mitreMapping: Array<{
    tactic: string;
    techniques: Array<{ id: string; name: string; result: string }>;
  }>;
  findings: Array<{
    id: string;
    severity: string;
    title: string;
    description: string;
    techniqueId: string;
    recommendation: string;
  }>;
  recommendations: string[];
  conclusion: string;
}

// ─── MITRE Tactic Order ─────────────────────────────────────────────────────

const TACTIC_ORDER = [
  "reconnaissance", "resource-development", "initial-access", "execution",
  "persistence", "privilege-escalation", "defense-evasion", "credential-access",
  "discovery", "lateral-movement", "collection", "command-and-control",
  "exfiltration", "impact"
];

// ─── Report Generation ──────────────────────────────────────────────────────

export async function generateReport(input: ReportInput): Promise<ReportData> {
  const op = input.operationData;
  const chain = op?.chain || [];
  const techniques = op?.techniques || [];
  const timeline = op?.timeline || [];
  const metrics = op?.metrics || {};
  const coverage = input.coverageData;

  const dateStr = new Date().toLocaleDateString('en-US', {
    year: 'numeric', month: 'long', day: 'numeric',
  });

  // Build attack chain results
  const attackChainResults = techniques.map((tech: any) => {
    const steps = tech.steps || [];
    const succeeded = steps.filter((s: any) => s.status === 'success').length;
    const failed = steps.filter((s: any) => s.status === 'failed').length;
    return {
      techniqueId: tech.id,
      techniqueName: tech.name,
      tactic: tech.tactic || 'unknown',
      status: tech.status || 'unknown',
      stepsExecuted: steps.length,
      stepsSucceeded: succeeded,
      detectionStatus: failed > 0 ? 'detected' : succeeded > 0 ? 'undetected' : 'not-tested',
    };
  });

  // Build MITRE mapping
  const tacticMap: Record<string, Array<{ id: string; name: string; result: string }>> = {};
  for (const tech of attackChainResults) {
    const tactic = tech.tactic;
    if (!tacticMap[tactic]) tacticMap[tactic] = [];
    tacticMap[tactic].push({
      id: tech.techniqueId,
      name: tech.techniqueName,
      result: tech.status,
    });
  }
  const mitreMapping = TACTIC_ORDER
    .filter(t => tacticMap[t])
    .map(t => ({ tactic: t, techniques: tacticMap[t] }));

  // Coverage analysis
  const coverageMatrix = coverage?.matrix || [];
  const coverageSummary = coverage?.summary || {};
  const gaps = coverageMatrix
    .filter((m: any) => m.coverageStatus === 'ops-only' || m.coverageStatus === 'none')
    .map((m: any) => ({
      techniqueId: m.techniqueId,
      techniqueName: m.techniqueName,
      tactic: m.tactic,
      recommendation: m.coverageStatus === 'ops-only'
        ? `Create detection rules for ${m.techniqueId} (${m.techniqueName}) - currently tested in operations but no SIEM detection exists.`
        : `Add both operation testing and detection rules for ${m.techniqueId} (${m.techniqueName}).`,
    }));

  // Generate findings from attack results
  const findings = attackChainResults
    .filter((r: any) => r.status === 'success' && r.detectionStatus === 'undetected')
    .map((r: any, i: number) => ({
      id: `F-${String(i + 1).padStart(3, '0')}`,
      severity: getSeverityForTactic(r.tactic),
      title: `Undetected ${r.techniqueName} (${r.techniqueId})`,
      description: `The ${r.techniqueName} technique was successfully executed during the engagement without triggering any detection alerts. This indicates a gap in the current detection capabilities for this attack vector.`,
      techniqueId: r.techniqueId,
      recommendation: `Implement detection rules for ${r.techniqueId} in your SIEM. Consider Sigma rules targeting the specific log sources and event patterns associated with this technique.`,
    }));

  // Calculate metrics
  const techniquesAttempted = attackChainResults.length;
  const techniquesSucceeded = attackChainResults.filter((r: any) => r.status === 'success').length;
  const tacticsCovered = new Set(attackChainResults.map((r: any) => r.tactic)).size;

  const reportMetrics = {
    totalSteps: metrics.totalSteps || chain.length,
    completedSteps: metrics.completedSteps || chain.filter((s: any) => s.finish).length,
    successRate: metrics.successRate || 0,
    detectionRate: metrics.detectionRate || 0,
    techniquesAttempted,
    techniquesSucceeded,
    tacticsCovered,
    avgConfidence: 0,
  };

  // Generate executive summary with LLM
  let executiveSummary = '';
  let recommendations: string[] = [];
  let conclusion = '';

  try {
    const llmResponse = await invokeLLM({
      messages: [
        {
          role: "system",
          content: "You are a senior penetration testing consultant at AceofCloud writing a post-engagement report. Write in a professional, technical but accessible tone. Do not use markdown formatting - write plain text paragraphs.",
        },
        {
          role: "user",
          content: `Generate three sections for a post-engagement report:

OPERATION: ${op?.name || 'Unknown'}
TYPE: ${input.engagementType || 'Purple Team Exercise'}
CLIENT: ${input.clientName || 'Client'}
TOTAL TECHNIQUES TESTED: ${techniquesAttempted}
TECHNIQUES SUCCEEDED: ${techniquesSucceeded}
SUCCESS RATE: ${reportMetrics.successRate}%
DETECTION RATE: ${reportMetrics.detectionRate}%
TACTICS COVERED: ${tacticsCovered}
DETECTION GAPS: ${gaps.length}
KEY FINDINGS: ${findings.length} undetected techniques

${input.customNotes ? `ADDITIONAL NOTES: ${input.customNotes}` : ''}

Return JSON with:
1. "executiveSummary" - 2-3 paragraphs summarizing the engagement, key findings, and overall security posture
2. "recommendations" - Array of 5-8 specific, actionable recommendations
3. "conclusion" - 1-2 paragraphs with final assessment and next steps`,
        },
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "report_sections",
          strict: true,
          schema: {
            type: "object",
            properties: {
              executiveSummary: { type: "string" },
              recommendations: { type: "array", items: { type: "string" } },
              conclusion: { type: "string" },
            },
            required: ["executiveSummary", "recommendations", "conclusion"],
            additionalProperties: false,
          },
        },
      },
    });

    const rawContent = llmResponse.choices?.[0]?.message?.content || "{}";
    const content = typeof rawContent === 'string' ? rawContent : JSON.stringify(rawContent);
    const parsed = JSON.parse(content);
    executiveSummary = parsed.executiveSummary || '';
    recommendations = parsed.recommendations || [];
    conclusion = parsed.conclusion || '';
  } catch (error) {
    console.error("LLM report generation failed:", error);
    executiveSummary = `This report presents the findings from the ${input.engagementType || 'purple team exercise'} conducted for ${input.clientName || 'the client'}. The engagement tested ${techniquesAttempted} MITRE ATT&CK techniques across ${tacticsCovered} tactics, achieving a ${reportMetrics.successRate}% success rate with a ${reportMetrics.detectionRate}% detection rate. ${findings.length} techniques were successfully executed without detection, indicating areas requiring immediate attention.`;
    recommendations = [
      "Implement detection rules for all identified coverage gaps",
      "Review and tune existing SIEM rules for the undetected techniques",
      "Conduct regular purple team exercises to validate detection improvements",
      "Enhance logging coverage for critical attack surfaces",
      "Establish a detection engineering program with regular rule validation",
    ];
    conclusion = `The engagement revealed ${findings.length} significant detection gaps that should be addressed as a priority. The overall detection coverage of ${coverageSummary.fullCoverage || 0} fully covered techniques out of ${coverageSummary.totalTechniques || techniquesAttempted} total demonstrates the current security posture and provides a clear roadmap for improvement.`;
  }

  return {
    metadata: {
      title: `Post-Engagement Security Assessment Report`,
      subtitle: op?.name || 'Security Assessment',
      author: 'Ace C3',
      company: 'AceofCloud',
      website: 'https://aceofcloud.com',
      date: dateStr,
      clientName: input.clientName || 'Client',
      engagementType: input.engagementType || 'Purple Team Exercise',
      operationId: input.operationId,
      operationName: op?.name || 'Unknown',
      classification: 'CONFIDENTIAL',
    },
    executiveSummary,
    scopeAndMethodology: `This ${input.engagementType || 'purple team exercise'} was conducted using the MITRE ATT&CK framework as the primary reference for adversary emulation. The engagement leveraged Caldera as the adversary emulation platform, executing ${techniquesAttempted} techniques across ${tacticsCovered} tactical phases. Each technique was mapped to specific MITRE ATT&CK identifiers and tested against the target environment's detection capabilities. Detection rules were auto-generated and validated using the AceofCloud Rule Validation Engine, covering Sigma, YARA, and Suricata rule formats.`,
    operationTimeline: timeline.map((t: any) => ({
      time: t.time || t.finishTime || '',
      event: t.abilityName || 'Unknown',
      status: t.status || 'unknown',
      techniqueId: t.techniqueId || '',
    })),
    attackChainResults,
    metrics: reportMetrics,
    detectionCoverage: {
      totalTechniques: coverageSummary.totalTechniques || techniquesAttempted,
      fullCoverage: coverageSummary.fullCoverage || 0,
      partialCoverage: coverageSummary.partialCoverage || 0,
      noCoverage: (coverageSummary.opsOnly || 0) + (coverageSummary.noCoverage || 0),
      coveragePercentage: coverageSummary.totalTechniques
        ? Math.round(((coverageSummary.fullCoverage + coverageSummary.partialCoverage) / coverageSummary.totalTechniques) * 100)
        : 0,
      gaps,
    },
    ruleValidation: {
      totalRules: 0,
      validRules: 0,
      avgEffectiveness: 0,
      rulesByType: {},
      topIssues: [],
    },
    mitreMapping,
    findings,
    recommendations,
    conclusion,
  };
}

function getSeverityForTactic(tactic: string): string {
  const m: Record<string, string> = {
    "credential-access": "critical",
    "exfiltration": "critical",
    "impact": "critical",
    "initial-access": "high",
    "execution": "high",
    "privilege-escalation": "high",
    "lateral-movement": "high",
    "defense-evasion": "high",
    "command-and-control": "high",
    "persistence": "medium",
    "discovery": "medium",
    "collection": "medium",
    "reconnaissance": "low",
    "resource-development": "low",
  };
  return m[tactic] || "medium";
}

// ─── HTML Report Renderer ───────────────────────────────────────────────────

export function renderReportHTML(report: ReportData): string {
  const { metadata, executiveSummary, scopeAndMethodology, operationTimeline, attackChainResults, metrics, detectionCoverage, mitreMapping, findings, recommendations, conclusion } = report;

  const severityColor = (s: string) => {
    if (s === 'critical') return '#ef4444';
    if (s === 'high') return '#f97316';
    if (s === 'medium') return '#eab308';
    return '#22c55e';
  };

  const statusColor = (s: string) => {
    if (s === 'success') return '#22c55e';
    if (s === 'failed' || s === 'detected') return '#ef4444';
    if (s === 'partial') return '#eab308';
    return '#6b7280';
  };

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${metadata.title}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Inter', sans-serif; color: #1a1a2e; background: #fff; line-height: 1.6; }
  .page { max-width: 900px; margin: 0 auto; padding: 40px; }
  
  /* Cover Page */
  .cover { min-height: 100vh; display: flex; flex-direction: column; justify-content: center; align-items: center; background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%); color: white; text-align: center; padding: 60px 40px; page-break-after: always; }
  .cover-logo { font-size: 28px; font-weight: 700; letter-spacing: 2px; color: #38bdf8; margin-bottom: 60px; }
  .cover h1 { font-size: 36px; font-weight: 700; margin-bottom: 12px; }
  .cover h2 { font-size: 20px; font-weight: 400; color: #94a3b8; margin-bottom: 40px; }
  .cover-meta { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; text-align: left; max-width: 500px; margin-top: 40px; }
  .cover-meta dt { color: #64748b; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; }
  .cover-meta dd { color: #e2e8f0; font-size: 14px; font-weight: 500; margin-bottom: 12px; }
  .cover-classification { margin-top: 60px; padding: 8px 24px; border: 2px solid #ef4444; color: #ef4444; font-weight: 600; font-size: 14px; letter-spacing: 2px; }
  
  /* Sections */
  h2 { font-size: 22px; font-weight: 700; color: #0f172a; margin: 40px 0 16px; padding-bottom: 8px; border-bottom: 2px solid #38bdf8; }
  h3 { font-size: 16px; font-weight: 600; color: #334155; margin: 24px 0 12px; }
  p { margin-bottom: 16px; color: #475569; font-size: 14px; }
  
  /* Tables */
  table { width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 13px; }
  th { background: #f1f5f9; color: #334155; font-weight: 600; text-align: left; padding: 10px 12px; border-bottom: 2px solid #e2e8f0; }
  td { padding: 8px 12px; border-bottom: 1px solid #f1f5f9; color: #475569; }
  tr:hover td { background: #f8fafc; }
  
  /* Metrics Grid */
  .metrics-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin: 20px 0; }
  .metric-card { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; text-align: center; }
  .metric-value { font-size: 28px; font-weight: 700; }
  .metric-label { font-size: 12px; color: #64748b; margin-top: 4px; }
  
  /* Status badges */
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
  .badge-success { background: #dcfce7; color: #166534; }
  .badge-failed { background: #fee2e2; color: #991b1b; }
  .badge-partial { background: #fef9c3; color: #854d0e; }
  .badge-critical { background: #fee2e2; color: #991b1b; }
  .badge-high { background: #ffedd5; color: #9a3412; }
  .badge-medium { background: #fef9c3; color: #854d0e; }
  .badge-low { background: #dcfce7; color: #166534; }
  
  /* Coverage bar */
  .coverage-bar { height: 24px; background: #f1f5f9; border-radius: 12px; overflow: hidden; display: flex; margin: 12px 0; }
  .coverage-full { background: #22c55e; }
  .coverage-partial { background: #eab308; }
  .coverage-none { background: #ef4444; }
  
  /* Finding card */
  .finding { border-left: 4px solid; padding: 16px; margin: 16px 0; background: #f8fafc; border-radius: 0 8px 8px 0; }
  
  /* Footer */
  .footer { margin-top: 60px; padding-top: 20px; border-top: 1px solid #e2e8f0; text-align: center; color: #94a3b8; font-size: 12px; }
  
  /* MITRE Heatmap */
  .mitre-grid { display: flex; flex-wrap: wrap; gap: 8px; margin: 16px 0; }
  .mitre-tactic { flex: 1; min-width: 120px; }
  .mitre-tactic-header { font-size: 11px; font-weight: 600; text-transform: uppercase; padding: 6px 8px; color: white; border-radius: 4px 4px 0 0; text-align: center; }
  .mitre-tech { font-size: 10px; padding: 4px 6px; border: 1px solid #e2e8f0; margin-top: -1px; }
  
  /* Recommendations */
  .rec-list { counter-reset: rec; list-style: none; padding: 0; }
  .rec-list li { counter-increment: rec; padding: 12px 12px 12px 48px; position: relative; margin-bottom: 8px; background: #f8fafc; border-radius: 8px; font-size: 14px; color: #475569; }
  .rec-list li::before { content: counter(rec); position: absolute; left: 12px; top: 12px; width: 24px; height: 24px; background: #38bdf8; color: white; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 12px; font-weight: 700; }
  
  @media print {
    .page { padding: 20px; }
    .cover { min-height: auto; padding: 40px; }
    h2 { page-break-before: auto; }
    table { page-break-inside: avoid; }
    .finding { page-break-inside: avoid; }
  }
</style>
</head>
<body>

<!-- Cover Page -->
<div class="cover">
  <div class="cover-logo">ACEOFCLOUD</div>
  <h1>${metadata.title}</h1>
  <h2>${metadata.subtitle}</h2>
  <dl class="cover-meta">
    <dt>Prepared For</dt><dd>${metadata.clientName}</dd>
    <dt>Engagement Type</dt><dd>${metadata.engagementType}</dd>
    <dt>Author</dt><dd>${metadata.author}</dd>
    <dt>Date</dt><dd>${metadata.date}</dd>
    <dt>Company</dt><dd>${metadata.company}</dd>
    <dt>Website</dt><dd>${metadata.website}</dd>
  </dl>
  <div class="cover-classification">${metadata.classification}</div>
</div>

<div class="page">

<!-- Table of Contents -->
<h2>Table of Contents</h2>
<ol style="font-size: 14px; color: #475569; padding-left: 20px; line-height: 2;">
  <li>Executive Summary</li>
  <li>Scope & Methodology</li>
  <li>Key Metrics</li>
  <li>Attack Chain Results</li>
  <li>MITRE ATT&CK Mapping</li>
  <li>Detection Coverage Analysis</li>
  <li>Findings</li>
  <li>Recommendations</li>
  <li>Conclusion</li>
</ol>

<!-- Executive Summary -->
<h2>1. Executive Summary</h2>
${executiveSummary.split('\n').filter(Boolean).map(p => `<p>${p}</p>`).join('')}

<!-- Scope & Methodology -->
<h2>2. Scope & Methodology</h2>
<p>${scopeAndMethodology}</p>

<!-- Key Metrics -->
<h2>3. Key Metrics</h2>
<div class="metrics-grid">
  <div class="metric-card">
    <div class="metric-value" style="color: #38bdf8;">${metrics.totalSteps}</div>
    <div class="metric-label">Total Steps Executed</div>
  </div>
  <div class="metric-card">
    <div class="metric-value" style="color: #22c55e;">${metrics.successRate}%</div>
    <div class="metric-label">Attack Success Rate</div>
  </div>
  <div class="metric-card">
    <div class="metric-value" style="color: #ef4444;">${metrics.detectionRate}%</div>
    <div class="metric-label">Detection Rate</div>
  </div>
  <div class="metric-card">
    <div class="metric-value" style="color: #a855f7;">${metrics.tacticsCovered}</div>
    <div class="metric-label">Tactics Covered</div>
  </div>
</div>
<div class="metrics-grid">
  <div class="metric-card">
    <div class="metric-value">${metrics.techniquesAttempted}</div>
    <div class="metric-label">Techniques Attempted</div>
  </div>
  <div class="metric-card">
    <div class="metric-value" style="color: #22c55e;">${metrics.techniquesSucceeded}</div>
    <div class="metric-label">Techniques Succeeded</div>
  </div>
  <div class="metric-card">
    <div class="metric-value">${metrics.completedSteps}</div>
    <div class="metric-label">Steps Completed</div>
  </div>
  <div class="metric-card">
    <div class="metric-value" style="color: #eab308;">${findings.length}</div>
    <div class="metric-label">Undetected Findings</div>
  </div>
</div>

<!-- Attack Chain Results -->
<h2>4. Attack Chain Results</h2>
<table>
  <thead>
    <tr>
      <th>Technique ID</th>
      <th>Technique Name</th>
      <th>Tactic</th>
      <th>Steps</th>
      <th>Status</th>
      <th>Detection</th>
    </tr>
  </thead>
  <tbody>
    ${attackChainResults.map((r: any) => `
    <tr>
      <td><code>${r.techniqueId}</code></td>
      <td>${r.techniqueName}</td>
      <td style="text-transform: capitalize;">${r.tactic.replace(/-/g, ' ')}</td>
      <td>${r.stepsSucceeded}/${r.stepsExecuted}</td>
      <td><span class="badge badge-${r.status === 'success' ? 'success' : r.status === 'failed' ? 'failed' : 'partial'}">${r.status}</span></td>
      <td><span class="badge badge-${r.detectionStatus === 'detected' ? 'failed' : r.detectionStatus === 'undetected' ? 'success' : 'partial'}">${r.detectionStatus}</span></td>
    </tr>`).join('')}
  </tbody>
</table>

<!-- MITRE ATT&CK Mapping -->
<h2>5. MITRE ATT&CK Mapping</h2>
<p>The following matrix shows the MITRE ATT&CK techniques tested during this engagement, organized by tactic phase.</p>
<div class="mitre-grid">
  ${mitreMapping.map(tm => {
    const colors: Record<string, string> = {
      'reconnaissance': '#475569', 'resource-development': '#64748b',
      'initial-access': '#dc2626', 'execution': '#ef4444',
      'persistence': '#ea580c', 'privilege-escalation': '#f97316',
      'defense-evasion': '#ca8a04', 'credential-access': '#eab308',
      'discovery': '#16a34a', 'lateral-movement': '#22c55e',
      'collection': '#0d9488', 'command-and-control': '#2563eb',
      'exfiltration': '#3b82f6', 'impact': '#7c3aed',
    };
    return `<div class="mitre-tactic">
      <div class="mitre-tactic-header" style="background: ${colors[tm.tactic] || '#64748b'};">${tm.tactic.replace(/-/g, ' ')}</div>
      ${tm.techniques.map(t => `<div class="mitre-tech" style="border-left: 3px solid ${statusColor(t.result)};">${t.id}: ${t.name}</div>`).join('')}
    </div>`;
  }).join('')}
</div>

<!-- Detection Coverage Analysis -->
<h2>6. Detection Coverage Analysis</h2>
<div class="metrics-grid" style="grid-template-columns: repeat(3, 1fr);">
  <div class="metric-card">
    <div class="metric-value" style="color: #22c55e;">${detectionCoverage.coveragePercentage}%</div>
    <div class="metric-label">Overall Coverage</div>
  </div>
  <div class="metric-card">
    <div class="metric-value" style="color: #22c55e;">${detectionCoverage.fullCoverage}</div>
    <div class="metric-label">Fully Covered</div>
  </div>
  <div class="metric-card">
    <div class="metric-value" style="color: #ef4444;">${detectionCoverage.noCoverage}</div>
    <div class="metric-label">Coverage Gaps</div>
  </div>
</div>
<div class="coverage-bar">
  <div class="coverage-full" style="width: ${detectionCoverage.totalTechniques ? (detectionCoverage.fullCoverage / detectionCoverage.totalTechniques) * 100 : 0}%;"></div>
  <div class="coverage-partial" style="width: ${detectionCoverage.totalTechniques ? (detectionCoverage.partialCoverage / detectionCoverage.totalTechniques) * 100 : 0}%;"></div>
  <div class="coverage-none" style="width: ${detectionCoverage.totalTechniques ? (detectionCoverage.noCoverage / detectionCoverage.totalTechniques) * 100 : 0}%;"></div>
</div>
${detectionCoverage.gaps.length > 0 ? `
<h3>Coverage Gaps</h3>
<table>
  <thead><tr><th>Technique</th><th>Tactic</th><th>Recommendation</th></tr></thead>
  <tbody>
    ${detectionCoverage.gaps.slice(0, 20).map(g => `
    <tr>
      <td><code>${g.techniqueId}</code> ${g.techniqueName}</td>
      <td style="text-transform: capitalize;">${g.tactic.replace(/-/g, ' ')}</td>
      <td style="font-size: 12px;">${g.recommendation}</td>
    </tr>`).join('')}
  </tbody>
</table>` : ''}

<!-- Findings -->
<h2>7. Findings</h2>
${findings.length === 0 ? '<p>No undetected techniques were identified during this engagement. All tested techniques were successfully detected by existing security controls.</p>' :
findings.map(f => `
<div class="finding" style="border-color: ${severityColor(f.severity)};">
  <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
    <strong style="font-size: 15px;">${f.id}: ${f.title}</strong>
    <span class="badge badge-${f.severity}">${f.severity}</span>
  </div>
  <p style="margin-bottom: 8px;">${f.description}</p>
  <p style="font-size: 13px; color: #334155;"><strong>Recommendation:</strong> ${f.recommendation}</p>
</div>`).join('')}

<!-- Recommendations -->
<h2>8. Recommendations</h2>
<ol class="rec-list">
  ${recommendations.map(r => `<li>${r}</li>`).join('')}
</ol>

<!-- Conclusion -->
<h2>9. Conclusion</h2>
${conclusion.split('\n').filter(Boolean).map(p => `<p>${p}</p>`).join('')}

<!-- Footer -->
<div class="footer">
  <p><strong>${metadata.company}</strong> | ${metadata.website}</p>
  <p>Prepared by ${metadata.author} | ${metadata.date}</p>
  <p style="margin-top: 8px; font-size: 11px;">This document is ${metadata.classification} and intended solely for the use of ${metadata.clientName}.</p>
</div>

</div>
</body>
</html>`;
}
