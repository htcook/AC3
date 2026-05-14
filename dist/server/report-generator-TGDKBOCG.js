import {
  init_llm,
  invokeLLM
} from "./chunk-WJ24GKGB.js";
import "./chunk-RUIEEOYK.js";
import "./chunk-NRYVRXXR.js";
import "./chunk-KFQGP6VL.js";

// server/lib/report-generator.ts
init_llm();
var TACTIC_ORDER = [
  "reconnaissance",
  "resource-development",
  "initial-access",
  "execution",
  "persistence",
  "privilege-escalation",
  "defense-evasion",
  "credential-access",
  "discovery",
  "lateral-movement",
  "collection",
  "command-and-control",
  "exfiltration",
  "impact"
];
async function generateReport(input) {
  const op = input.operationData;
  const chain = op?.chain || [];
  const techniques = op?.techniques || [];
  const timeline = op?.timeline || [];
  const metrics = op?.metrics || {};
  const coverage = input.coverageData;
  const dateStr = (/* @__PURE__ */ new Date()).toLocaleDateString("en-US", {
    year: "numeric",
    month: "long",
    day: "numeric"
  });
  const attackChainResults = techniques.map((tech) => {
    const steps = tech.steps || [];
    const succeeded = steps.filter((s) => s.status === "success").length;
    const failed = steps.filter((s) => s.status === "failed").length;
    return {
      techniqueId: tech.id,
      techniqueName: tech.name,
      tactic: tech.tactic || "unknown",
      status: tech.status || "unknown",
      stepsExecuted: steps.length,
      stepsSucceeded: succeeded,
      detectionStatus: failed > 0 ? "detected" : succeeded > 0 ? "undetected" : "not-tested"
    };
  });
  const tacticMap = {};
  for (const tech of attackChainResults) {
    const tactic = tech.tactic;
    if (!tacticMap[tactic]) tacticMap[tactic] = [];
    tacticMap[tactic].push({
      id: tech.techniqueId,
      name: tech.techniqueName,
      result: tech.status
    });
  }
  const mitreMapping = TACTIC_ORDER.filter((t) => tacticMap[t]).map((t) => ({ tactic: t, techniques: tacticMap[t] }));
  const coverageMatrix = coverage?.matrix || [];
  const coverageSummary = coverage?.summary || {};
  const gaps = coverageMatrix.filter((m) => m.coverageStatus === "ops-only" || m.coverageStatus === "none").map((m) => ({
    techniqueId: m.techniqueId,
    techniqueName: m.techniqueName,
    tactic: m.tactic,
    recommendation: m.coverageStatus === "ops-only" ? `Create detection rules for ${m.techniqueId} (${m.techniqueName}) - currently tested in operations but no SIEM detection exists.` : `Add both operation testing and detection rules for ${m.techniqueId} (${m.techniqueName}).`
  }));
  const findings = attackChainResults.filter((r) => r.status === "success" && r.detectionStatus === "undetected").map((r, i) => ({
    id: `F-${String(i + 1).padStart(3, "0")}`,
    severity: getSeverityForTactic(r.tactic),
    title: `Undetected ${r.techniqueName} (${r.techniqueId})`,
    description: `The ${r.techniqueName} technique was successfully executed during the engagement without triggering any detection alerts. This indicates a gap in the current detection capabilities for this attack vector.`,
    techniqueId: r.techniqueId,
    recommendation: `Implement detection rules for ${r.techniqueId} in your SIEM. Consider Sigma rules targeting the specific log sources and event patterns associated with this technique.`
  }));
  const techniquesAttempted = attackChainResults.length;
  const techniquesSucceeded = attackChainResults.filter((r) => r.status === "success").length;
  const tacticsCovered = new Set(attackChainResults.map((r) => r.tactic)).size;
  const reportMetrics = {
    totalSteps: metrics.totalSteps || chain.length,
    completedSteps: metrics.completedSteps || chain.filter((s) => s.finish).length,
    successRate: metrics.successRate || 0,
    detectionRate: metrics.detectionRate || 0,
    techniquesAttempted,
    techniquesSucceeded,
    tacticsCovered,
    avgConfidence: 0
  };
  let executiveSummary = "";
  let recommendations = [];
  let conclusion = "";
  try {
    const llmResponse = await invokeLLM({
      _caller: "report-generator",
      _priority: "bulk",
      messages: [
        {
          role: "system",
          content: "You are a senior penetration testing consultant at Ace of Cloud LLC writing a post-engagement report for the AC3 (Cyber Campaign Command) platform. Write in a professional, technical but accessible tone. Do not use markdown formatting - write plain text paragraphs."
        },
        {
          role: "user",
          content: `Generate three sections for a post-engagement report:

OPERATION: ${op?.name || "Unknown"}
TYPE: ${input.engagementType || "Purple Team Exercise"}
CLIENT: ${input.clientName || "Client"}
TOTAL TECHNIQUES TESTED: ${techniquesAttempted}
TECHNIQUES SUCCEEDED: ${techniquesSucceeded}
SUCCESS RATE: ${reportMetrics.successRate}%
DETECTION RATE: ${reportMetrics.detectionRate}%
TACTICS COVERED: ${tacticsCovered}
DETECTION GAPS: ${gaps.length}
KEY FINDINGS: ${findings.length} undetected techniques

${input.customNotes ? `ADDITIONAL NOTES: ${input.customNotes}` : ""}

Return JSON with:
1. "executiveSummary" - 2-3 paragraphs summarizing the engagement, key findings, and overall security posture
2. "recommendations" - Array of 5-8 specific, actionable recommendations
3. "conclusion" - 1-2 paragraphs with final assessment and next steps`
        }
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
              conclusion: { type: "string" }
            },
            required: ["executiveSummary", "recommendations", "conclusion"],
            additionalProperties: false
          }
        }
      }
    });
    const rawContent = llmResponse.choices?.[0]?.message?.content || "{}";
    const content = typeof rawContent === "string" ? rawContent : JSON.stringify(rawContent);
    const parsed = JSON.parse(content);
    executiveSummary = parsed.executiveSummary || "";
    recommendations = parsed.recommendations || [];
    conclusion = parsed.conclusion || "";
  } catch (error) {
    console.error("LLM report generation failed:", error);
    executiveSummary = `This report presents the findings from the ${input.engagementType || "purple team exercise"} conducted for ${input.clientName || "the client"}. The engagement tested ${techniquesAttempted} MITRE ATT&CK techniques across ${tacticsCovered} tactics, achieving a ${reportMetrics.successRate}% success rate with a ${reportMetrics.detectionRate}% detection rate. ${findings.length} techniques were successfully executed without detection, indicating areas requiring immediate attention.`;
    recommendations = [
      "Implement detection rules for all identified coverage gaps",
      "Review and tune existing SIEM rules for the undetected techniques",
      "Conduct regular purple team exercises to validate detection improvements",
      "Enhance logging coverage for critical attack surfaces",
      "Establish a detection engineering program with regular rule validation"
    ];
    conclusion = `The engagement revealed ${findings.length} significant detection gaps that should be addressed as a priority. The overall detection coverage of ${coverageSummary.fullCoverage || 0} fully covered techniques out of ${coverageSummary.totalTechniques || techniquesAttempted} total demonstrates the current security posture and provides a clear roadmap for improvement.`;
  }
  let discoveryRecon = void 0;
  let toolEvidence = void 0;
  if (input.engagementOpsData?.assets?.length) {
    const opsAssets = input.engagementOpsData.assets;
    const portMap = /* @__PURE__ */ new Map();
    for (const a of opsAssets) {
      for (const p of a.knownPorts || []) {
        const port = typeof p === "number" ? p : p.port || 0;
        const svc = typeof p === "object" ? p.service || "unknown" : "unknown";
        if (!portMap.has(port)) portMap.set(port, { services: /* @__PURE__ */ new Set(), assets: /* @__PURE__ */ new Set() });
        const entry = portMap.get(port);
        entry.services.add(svc);
        entry.assets.add(a.hostname);
      }
    }
    const portSummary = Array.from(portMap.entries()).sort((a, b) => b[1].assets.size - a[1].assets.size).slice(0, 30).map(([port, data]) => ({ port, service: Array.from(data.services).join(", "), assetCount: data.assets.size }));
    const svcMap = /* @__PURE__ */ new Map();
    for (const a of opsAssets) {
      for (const p of a.knownPorts || []) {
        if (typeof p === "object" && p.service) {
          if (!svcMap.has(p.service)) svcMap.set(p.service, { count: 0, ports: /* @__PURE__ */ new Set() });
          const entry = svcMap.get(p.service);
          entry.count++;
          entry.ports.add(p.port || 0);
        }
      }
      for (const svc of a.passiveRecon?.services || []) {
        const name = svc.service || svc.name || "unknown";
        if (!svcMap.has(name)) svcMap.set(name, { count: 0, ports: /* @__PURE__ */ new Set() });
        const entry = svcMap.get(name);
        entry.count++;
        if (svc.port) entry.ports.add(svc.port);
      }
    }
    const serviceSummary = Array.from(svcMap.entries()).sort((a, b) => b[1].count - a[1].count).slice(0, 20).map(([svc, data]) => ({ service: svc, count: data.count, ports: Array.from(data.ports).sort((a, b) => a - b) }));
    const techMap = /* @__PURE__ */ new Map();
    for (const a of opsAssets) {
      for (const t of a.passiveRecon?.technologies || []) {
        techMap.set(t, (techMap.get(t) || 0) + 1);
      }
      for (const tr of a.toolResults || []) {
        if (tr.tool === "httpx" && tr.findings) {
          for (const f of tr.findings) {
            if (f.includes("Tech:") || f.includes("tech:")) {
              const t = f.replace(/^.*[Tt]ech:\s*/, "").trim();
              if (t) techMap.set(t, (techMap.get(t) || 0) + 1);
            }
          }
        }
      }
    }
    const techSummary = Array.from(techMap.entries()).sort((a, b) => b[1] - a[1]).slice(0, 20).map(([tech, count]) => ({ technology: tech, count }));
    const assetSummaries = opsAssets.map((a) => {
      const ports = (a.knownPorts || []).length;
      const svcs = new Set((a.knownPorts || []).filter((p) => typeof p === "object" && p.service).map((p) => p.service)).size;
      const tech = (a.passiveRecon?.technologies || []).length;
      const tools = (a.toolResults || []).length;
      const findingsCount = (a.toolResults || []).reduce((sum, tr) => sum + (tr.findings?.length || 0), 0);
      return {
        hostname: a.hostname,
        ip: a.ip || "unknown",
        type: a.type || "unknown",
        status: a.status || "unknown",
        portsFound: ports,
        servicesFound: svcs,
        techFound: tech,
        toolsRun: tools,
        findingsCount,
        riskSignals: a.passiveRecon?.riskSignals || []
      };
    });
    const totalToolRuns = opsAssets.reduce((sum, a) => sum + (a.toolResults?.length || 0), 0);
    discoveryRecon = {
      totalAssets: opsAssets.length,
      totalPorts: portMap.size,
      totalServices: svcMap.size,
      totalTechnologies: techMap.size,
      totalToolRuns,
      portSummary,
      serviceSummary,
      techSummary,
      assetSummaries
    };
    toolEvidence = [];
    for (const a of opsAssets) {
      for (const tr of a.toolResults || []) {
        toolEvidence.push({
          asset: a.hostname,
          tool: tr.tool,
          command: tr.command || "",
          exitCode: tr.exitCode ?? -1,
          duration: tr.duration || "",
          findings: tr.findings || [],
          outputPreview: tr.outputPreview || ""
        });
      }
    }
  }
  return {
    metadata: {
      title: `Post-Engagement Security Assessment Report`,
      subtitle: op?.name || "Security Assessment",
      author: "Ace of Cloud LLC",
      company: "Ace of Cloud LLC",
      website: "https://aceofcloud.com",
      date: dateStr,
      clientName: input.clientName || "Client",
      engagementType: input.engagementType || "Purple Team Exercise",
      operationId: input.operationId,
      operationName: op?.name || "Unknown",
      classification: "CONFIDENTIAL"
    },
    executiveSummary,
    scopeAndMethodology: `This ${input.engagementType || "purple team exercise"} was conducted using the MITRE ATT&CK framework as the primary reference for adversary emulation. The engagement leveraged the Cyber C2 adversary emulation platform, executing ${techniquesAttempted} techniques across ${tacticsCovered} tactical phases. Each technique was mapped to specific MITRE ATT&CK identifiers and tested against the target environment's detection capabilities. Detection rules were auto-generated and validated using the AC3 Rule Validation Engine, covering Sigma, YARA, and Suricata rule formats.`,
    operationTimeline: timeline.map((t) => ({
      time: t.time || t.finishTime || "",
      event: t.abilityName || "Unknown",
      status: t.status || "unknown",
      techniqueId: t.techniqueId || ""
    })),
    attackChainResults,
    metrics: reportMetrics,
    detectionCoverage: {
      totalTechniques: coverageSummary.totalTechniques || techniquesAttempted,
      fullCoverage: coverageSummary.fullCoverage || 0,
      partialCoverage: coverageSummary.partialCoverage || 0,
      noCoverage: (coverageSummary.opsOnly || 0) + (coverageSummary.noCoverage || 0),
      coveragePercentage: coverageSummary.totalTechniques ? Math.round((coverageSummary.fullCoverage + coverageSummary.partialCoverage) / coverageSummary.totalTechniques * 100) : 0,
      gaps
    },
    ruleValidation: {
      totalRules: 0,
      validRules: 0,
      avgEffectiveness: 0,
      rulesByType: {},
      topIssues: []
    },
    mitreMapping,
    findings,
    recommendations,
    conclusion,
    discoveryRecon,
    toolEvidence
  };
}
function getSeverityForTactic(tactic) {
  const m = {
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
    "resource-development": "low"
  };
  return m[tactic] || "medium";
}
function renderReportHTML(report) {
  const { metadata, executiveSummary, scopeAndMethodology, operationTimeline, attackChainResults, metrics, detectionCoverage, mitreMapping, findings, recommendations, conclusion, complianceAuthorization } = report;
  const severityColor = (s) => {
    if (s === "critical") return "#ef4444";
    if (s === "high") return "#f97316";
    if (s === "medium") return "#eab308";
    return "#22c55e";
  };
  const statusColor = (s) => {
    if (s === "success") return "#22c55e";
    if (s === "failed" || s === "detected") return "#ef4444";
    if (s === "partial") return "#eab308";
    return "#6b7280";
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
${executiveSummary.split("\n").filter(Boolean).map((p) => `<p>${p}</p>`).join("")}

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
    ${attackChainResults.map((r) => `
    <tr>
      <td><code>${r.techniqueId}</code></td>
      <td>${r.techniqueName}</td>
      <td style="text-transform: capitalize;">${r.tactic.replace(/-/g, " ")}</td>
      <td>${r.stepsSucceeded}/${r.stepsExecuted}</td>
      <td><span class="badge badge-${r.status === "success" ? "success" : r.status === "failed" ? "failed" : "partial"}">${r.status}</span></td>
      <td><span class="badge badge-${r.detectionStatus === "detected" ? "failed" : r.detectionStatus === "undetected" ? "success" : "partial"}">${r.detectionStatus}</span></td>
    </tr>`).join("")}
  </tbody>
</table>

<!-- MITRE ATT&CK Mapping -->
<h2>5. MITRE ATT&CK Mapping</h2>
<p>The following matrix shows the MITRE ATT&CK techniques tested during this engagement, organized by tactic phase.</p>
<div class="mitre-grid">
  ${mitreMapping.map((tm) => {
    const colors = {
      "reconnaissance": "#475569",
      "resource-development": "#64748b",
      "initial-access": "#dc2626",
      "execution": "#ef4444",
      "persistence": "#ea580c",
      "privilege-escalation": "#f97316",
      "defense-evasion": "#ca8a04",
      "credential-access": "#eab308",
      "discovery": "#16a34a",
      "lateral-movement": "#22c55e",
      "collection": "#0d9488",
      "command-and-control": "#2563eb",
      "exfiltration": "#3b82f6",
      "impact": "#7c3aed"
    };
    return `<div class="mitre-tactic">
      <div class="mitre-tactic-header" style="background: ${colors[tm.tactic] || "#64748b"};">${tm.tactic.replace(/-/g, " ")}</div>
      ${tm.techniques.map((t) => `<div class="mitre-tech" style="border-left: 3px solid ${statusColor(t.result)};">${t.id}: ${t.name}</div>`).join("")}
    </div>`;
  }).join("")}
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
  <div class="coverage-full" style="width: ${detectionCoverage.totalTechniques ? detectionCoverage.fullCoverage / detectionCoverage.totalTechniques * 100 : 0}%;"></div>
  <div class="coverage-partial" style="width: ${detectionCoverage.totalTechniques ? detectionCoverage.partialCoverage / detectionCoverage.totalTechniques * 100 : 0}%;"></div>
  <div class="coverage-none" style="width: ${detectionCoverage.totalTechniques ? detectionCoverage.noCoverage / detectionCoverage.totalTechniques * 100 : 0}%;"></div>
</div>
${detectionCoverage.gaps.length > 0 ? `
<h3>Coverage Gaps</h3>
<table>
  <thead><tr><th>Technique</th><th>Tactic</th><th>Recommendation</th></tr></thead>
  <tbody>
    ${detectionCoverage.gaps.slice(0, 20).map((g) => `
    <tr>
      <td><code>${g.techniqueId}</code> ${g.techniqueName}</td>
      <td style="text-transform: capitalize;">${g.tactic.replace(/-/g, " ")}</td>
      <td style="font-size: 12px;">${g.recommendation}</td>
    </tr>`).join("")}
  </tbody>
</table>` : ""}

<!-- Findings -->
<h2>7. Findings</h2>
${findings.length === 0 ? "<p>No undetected techniques were identified during this engagement. All tested techniques were successfully detected by existing security controls.</p>" : findings.map((f) => `
<div class="finding" style="border-color: ${severityColor(f.severity)};">
  <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
    <strong style="font-size: 15px;">${f.id}: ${f.title}</strong>
    <span class="badge badge-${f.severity}">${f.severity}</span>
  </div>
  <p style="margin-bottom: 8px;">${f.description}</p>
  <p style="font-size: 13px; color: #334155;"><strong>Recommendation:</strong> ${f.recommendation}</p>
</div>`).join("")}

<!-- Compliance & Authorization -->
${complianceAuthorization ? `
<h2>8. Compliance &amp; Authorization</h2>
<p>This section documents the Rules of Engagement (ROE) authorization and provides an audit trail of all offensive actions conducted during this engagement.</p>

<h3 style="font-size: 16px; margin: 24px 0 12px; color: #1e293b;">8.1 Rules of Engagement Status</h3>
<table>
  <tbody>
    <tr><td style="font-weight: 600; width: 200px;">ROE Status</td><td><span class="badge badge-${complianceAuthorization.roeStatus === "signed" ? "low" : complianceAuthorization.roeStatus === "expired" ? "critical" : "medium"}">${complianceAuthorization.roeStatus.toUpperCase()}</span></td></tr>
    <tr><td style="font-weight: 600;">Signed Date</td><td>${complianceAuthorization.roeSignedDate || "N/A"}</td></tr>
    <tr><td style="font-weight: 600;">Expiry Date</td><td>${complianceAuthorization.roeExpiryDate || "N/A"}</td></tr>
    <tr><td style="font-weight: 600;">Signer</td><td>${complianceAuthorization.roeSignerName || "N/A"} ${complianceAuthorization.roeSignerEmail ? "(" + complianceAuthorization.roeSignerEmail + ")" : ""}</td></tr>
    <tr><td style="font-weight: 600;">Document</td><td>${complianceAuthorization.roeDocumentUrl ? '<a href="' + complianceAuthorization.roeDocumentUrl + '" style="color: #38bdf8;">View Signed ROE Document</a>' : "Not uploaded"}</td></tr>
  </tbody>
</table>

${complianceAuthorization.roeScope ? `
<h3 style="font-size: 16px; margin: 24px 0 12px; color: #1e293b;">8.2 Authorized Scope</h3>
<table>
  <tbody>
    ${(complianceAuthorization.roeScope.domains || []).length > 0 ? '<tr><td style="font-weight: 600; width: 200px;">Domains</td><td>' + complianceAuthorization.roeScope.domains.join(", ") + "</td></tr>" : ""}
    ${(complianceAuthorization.roeScope.ipRanges || []).length > 0 ? '<tr><td style="font-weight: 600;">IP Ranges</td><td>' + complianceAuthorization.roeScope.ipRanges.join(", ") + "</td></tr>" : ""}
    ${(complianceAuthorization.roeScope.exclusions || []).length > 0 ? '<tr><td style="font-weight: 600;">Exclusions</td><td>' + complianceAuthorization.roeScope.exclusions.join(", ") + "</td></tr>" : ""}
    ${complianceAuthorization.roeScope.restrictions ? '<tr><td style="font-weight: 600;">Restrictions</td><td>' + complianceAuthorization.roeScope.restrictions + "</td></tr>" : ""}
  </tbody>
</table>` : ""}

<h3 style="font-size: 16px; margin: 24px 0 12px; color: #1e293b;">8.3 Authorization Summary</h3>
<div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; margin-bottom: 20px;">
  <div style="background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 8px; padding: 16px; text-align: center;">
    <div style="font-size: 24px; font-weight: 700; color: #16a34a;">${complianceAuthorization.actionsUnderROE}</div>
    <div style="font-size: 12px; color: #166534;">Actions Under Valid ROE</div>
  </div>
  <div style="background: ${complianceAuthorization.blockedActions > 0 ? "#fef2f2" : "#f0fdf4"}; border: 1px solid ${complianceAuthorization.blockedActions > 0 ? "#fecaca" : "#bbf7d0"}; border-radius: 8px; padding: 16px; text-align: center;">
    <div style="font-size: 24px; font-weight: 700; color: ${complianceAuthorization.blockedActions > 0 ? "#dc2626" : "#16a34a"};">${complianceAuthorization.blockedActions}</div>
    <div style="font-size: 12px; color: ${complianceAuthorization.blockedActions > 0 ? "#991b1b" : "#166534"};">Blocked (No/Expired ROE)</div>
  </div>
  <div style="background: #eff6ff; border: 1px solid #bfdbfe; border-radius: 8px; padding: 16px; text-align: center;">
    <div style="font-size: 24px; font-weight: 700; color: #2563eb;">${complianceAuthorization.totalActions}</div>
    <div style="font-size: 12px; color: #1e40af;">Total Logged Actions</div>
  </div>
</div>

${complianceAuthorization.auditLogEntries.length > 0 ? `
<h3 style="font-size: 16px; margin: 24px 0 12px; color: #1e293b;">8.4 Offensive Action Audit Trail</h3>
<table>
  <thead>
    <tr>
      <th>Timestamp</th>
      <th>Operator</th>
      <th>Action</th>
      <th>Risk Tier</th>
      <th>Target</th>
      <th>Result</th>
      <th>ROE</th>
    </tr>
  </thead>
  <tbody>
    ${complianceAuthorization.auditLogEntries.slice(0, 50).map((e) => `
    <tr>
      <td style="font-size: 11px; white-space: nowrap;">${e.timestamp}</td>
      <td style="font-size: 12px;">${e.operator}</td>
      <td style="font-size: 12px;">${e.actionType.replace(/_/g, " ")}</td>
      <td><span class="badge badge-${e.riskTier === "red" ? "critical" : e.riskTier === "orange" ? "high" : "medium"}">${e.riskTier}</span></td>
      <td style="font-size: 12px; font-family: monospace;">${e.target}</td>
      <td><span class="badge badge-${e.result === "success" ? "low" : e.result === "blocked" ? "critical" : "medium"}">${e.result}</span></td>
      <td style="font-size: 12px;">${e.roeStatus}</td>
    </tr>`).join("")}
  </tbody>
</table>
${complianceAuthorization.auditLogEntries.length > 50 ? '<p style="font-size: 12px; color: #64748b; margin-top: 8px;">Showing 50 of ' + complianceAuthorization.auditLogEntries.length + " total audit log entries.</p>" : ""}
` : "<p>No offensive actions were logged for this engagement.</p>"}

<p style="margin-top: 16px;"><strong>Compliance Statement:</strong> ${complianceAuthorization.roeStatus === "signed" ? "All offensive actions documented in this report were conducted under a valid, signed Rules of Engagement document. The engagement team operated within the authorized scope and timeframe as defined by the ROE." : complianceAuthorization.roeStatus === "expired" ? "WARNING: The Rules of Engagement for this engagement have expired. Some actions may have been conducted after ROE expiry. Review the audit trail above for details." : "WARNING: No signed Rules of Engagement document was found for this engagement. This may indicate a compliance gap that should be addressed."}</p>
` : ""}

<!-- Discovery & Reconnaissance Summary -->
${report.discoveryRecon ? `
<h2>${complianceAuthorization ? "9" : "8"}. Discovery &amp; Reconnaissance Summary</h2>
<p>The following section presents aggregated findings from passive reconnaissance (OSINT, Shodan, Censys, crt.sh, SecurityTrails) and active discovery tools (naabu, ScanForge, httpx) executed across all in-scope assets.</p>

<div class="metrics-grid">
  <div class="metric-card"><div class="metric-value" style="color: #f97316;">${report.discoveryRecon.totalAssets}</div><div class="metric-label">Assets Discovered</div></div>
  <div class="metric-card"><div class="metric-value" style="color: #22d3ee;">${report.discoveryRecon.totalPorts}</div><div class="metric-label">Unique Ports</div></div>
  <div class="metric-card"><div class="metric-value" style="color: #3b82f6;">${report.discoveryRecon.totalServices}</div><div class="metric-label">Unique Services</div></div>
  <div class="metric-card"><div class="metric-value" style="color: #a855f7;">${report.discoveryRecon.totalTechnologies}</div><div class="metric-label">Technologies</div></div>
</div>

<h3>Port Frequency</h3>
<table>
  <thead><tr><th>Port</th><th>Service(s)</th><th>Asset Count</th></tr></thead>
  <tbody>
    ${report.discoveryRecon.portSummary.map((p) => `<tr><td style="font-family: monospace; font-weight: 600;">${p.port}</td><td>${p.service}</td><td>${p.assetCount}</td></tr>`).join("")}
  </tbody>
</table>

${report.discoveryRecon.serviceSummary.length > 0 ? `
<h3>Service Distribution</h3>
<table>
  <thead><tr><th>Service</th><th>Instances</th><th>Ports</th></tr></thead>
  <tbody>
    ${report.discoveryRecon.serviceSummary.map((s) => `<tr><td>${s.service}</td><td>${s.count}</td><td style="font-family: monospace; font-size: 11px;">${s.ports.join(", ")}</td></tr>`).join("")}
  </tbody>
</table>
` : ""}

${report.discoveryRecon.techSummary.length > 0 ? `
<h3>Technology Stack</h3>
<div style="display: flex; flex-wrap: wrap; gap: 8px; margin: 12px 0;">
  ${report.discoveryRecon.techSummary.map((t) => `<span style="background: #f3e8ff; color: #7c3aed; padding: 4px 12px; border-radius: 16px; font-size: 12px; font-weight: 500;">${t.technology} (${t.count})</span>`).join("")}
</div>
` : ""}

<h3>Per-Asset Summary</h3>
<table>
  <thead><tr><th>Hostname</th><th>IP</th><th>Type</th><th>Status</th><th>Ports</th><th>Services</th><th>Tech</th><th>Tools</th><th>Findings</th></tr></thead>
  <tbody>
    ${report.discoveryRecon.assetSummaries.map((a) => `<tr>
      <td style="font-family: monospace; font-weight: 500;">${a.hostname}</td>
      <td style="font-family: monospace; font-size: 11px;">${a.ip}</td>
      <td>${a.type}</td>
      <td><span class="badge" style="background: ${a.status === "compromised" ? "#fef2f2" : a.status === "vulnerable" ? "#fffbeb" : a.status === "scanned" ? "#eff6ff" : "#f0fdf4"}; color: ${a.status === "compromised" ? "#dc2626" : a.status === "vulnerable" ? "#d97706" : a.status === "scanned" ? "#2563eb" : "#16a34a"};">${a.status}</span></td>
      <td style="text-align: center;">${a.portsFound}</td>
      <td style="text-align: center;">${a.servicesFound}</td>
      <td style="text-align: center;">${a.techFound}</td>
      <td style="text-align: center;">${a.toolsRun}</td>
      <td style="text-align: center; ${a.findingsCount > 0 ? "color: #dc2626; font-weight: 600;" : ""}">${a.findingsCount}</td>
    </tr>${a.riskSignals.length > 0 ? `<tr><td colspan="9" style="padding: 4px 12px 8px; background: #fffbeb; font-size: 11px; color: #92400e;"><strong>Risk Signals:</strong> ${a.riskSignals.join(" | ")}</td></tr>` : ""}`).join("")}
  </tbody>
</table>
` : ""}

<!-- Tool Evidence -->
${report.toolEvidence && report.toolEvidence.length > 0 ? `
<h2>${complianceAuthorization ? "10" : "9"}. Tool Execution Evidence</h2>
<p>Complete record of all security tools executed during the engagement, including commands, exit codes, and key findings. This section provides the forensic evidence chain for all automated testing performed.</p>

<p style="font-size: 12px; color: #64748b;"><strong>Total tool executions:</strong> ${report.toolEvidence.length}</p>

${report.toolEvidence.map((te, idx) => `
<div style="border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin: 12px 0; page-break-inside: avoid;">
  <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
    <span style="background: ${te.tool === "scanforge-discovery" || te.tool === "scanforge-discovery" ? "#eff6ff" : te.tool === "naabu" ? "#ecfeff" : te.tool === "httpx" ? "#faf5ff" : te.tool === "nuclei" ? "#fef2f2" : te.tool === "zap" ? "#fff7ed" : "#f0fdf4"}; color: ${te.tool === "scanforge-discovery" || te.tool === "scanforge-discovery" ? "#2563eb" : te.tool === "naabu" ? "#0891b2" : te.tool === "httpx" ? "#7c3aed" : te.tool === "nuclei" ? "#dc2626" : te.tool === "zap" ? "#ea580c" : "#16a34a"}; padding: 2px 10px; border-radius: 4px; font-size: 12px; font-weight: 600;">${te.tool}</span>
    <span style="font-family: monospace; font-size: 12px; color: #64748b;">${te.asset}</span>
    <span style="margin-left: auto; font-size: 11px; color: ${te.exitCode === 0 ? "#16a34a" : "#dc2626"};">${te.exitCode === 0 ? "\u2713 Success" : "\u2717 Exit " + te.exitCode}${te.duration ? " | " + te.duration : ""}</span>
  </div>
  ${te.command ? `<div style="background: #0f172a; color: #a5f3fc; padding: 8px 12px; border-radius: 4px; font-family: monospace; font-size: 11px; overflow-x: auto; white-space: nowrap; margin-bottom: 8px;">$ ${te.command}</div>` : ""}
  ${te.findings.length > 0 ? `<div style="margin-top: 8px;"><strong style="font-size: 12px; color: #334155;">Findings (${te.findings.length}):</strong><ul style="margin: 4px 0 0 16px; padding: 0;">${te.findings.slice(0, 10).map((f) => `<li style="font-size: 12px; color: #b45309; margin: 2px 0;">${f}</li>`).join("")}${te.findings.length > 10 ? `<li style="font-size: 11px; color: #64748b;">+${te.findings.length - 10} more findings</li>` : ""}</ul></div>` : ""}
  ${te.outputPreview ? `<details style="margin-top: 8px;"><summary style="font-size: 11px; color: #64748b; cursor: pointer;">Raw output preview</summary><pre style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 4px; padding: 8px; font-size: 10px; max-height: 200px; overflow: auto; margin-top: 4px;">${te.outputPreview}</pre></details>` : ""}
</div>
`).join("")}
` : ""}

<!-- OWASP Top 10 Coverage -->
${report.owaspCoverage ? `
<h2>OWASP Top 10:2025 Coverage Analysis</h2>
<p>This section evaluates the engagement's testing coverage against the OWASP Top 10:2025 vulnerability categories. Each category is assessed based on the tools executed, findings discovered, and depth of testing performed.</p>

<div class="metrics-grid">
  <div class="metric-card"><div class="metric-value" style="color: ${report.owaspCoverage.overallScore >= 80 ? "#22c55e" : report.owaspCoverage.overallScore >= 60 ? "#eab308" : "#ef4444"};">${report.owaspCoverage.overallScore}%</div><div class="metric-label">Overall Score</div></div>
  <div class="metric-card"><div class="metric-value" style="color: #22c55e;">${report.owaspCoverage.testedCategories}</div><div class="metric-label">Fully Tested</div></div>
  <div class="metric-card"><div class="metric-value" style="color: #eab308;">${report.owaspCoverage.partialCategories}</div><div class="metric-label">Partially Tested</div></div>
  <div class="metric-card"><div class="metric-value" style="color: #ef4444;">${report.owaspCoverage.untestedCategories}</div><div class="metric-label">Not Tested</div></div>
</div>

<div style="display: inline-block; padding: 6px 16px; border-radius: 8px; font-weight: 700; font-size: 18px; margin: 12px 0; background: ${report.owaspCoverage.grade === "A" || report.owaspCoverage.grade === "A+" ? "#dcfce7; color: #166534" : report.owaspCoverage.grade === "B" ? "#fef9c3; color: #854d0e" : report.owaspCoverage.grade === "C" ? "#fed7aa; color: #9a3412" : "#fecaca; color: #991b1b"};">
  Grade: ${report.owaspCoverage.grade}
</div>

<table>
<tr><th>Category</th><th>Status</th><th>Score</th><th>Tools Used</th><th>Findings</th></tr>
${report.owaspCoverage.categories.map((c) => `<tr>
  <td><strong>${c.id}</strong><br><span style="font-size: 11px; color: #64748b;">${c.name}</span></td>
  <td><span class="badge" style="background: ${c.status === "tested" ? "#dcfce7; color: #166534" : c.status === "partial" ? "#fef9c3; color: #854d0e" : c.status === "not_applicable" ? "#f1f5f9; color: #64748b" : "#fecaca; color: #991b1b"};">${c.status === "tested" ? "Tested" : c.status === "partial" ? "Partial" : c.status === "not_applicable" ? "N/A" : "Not Tested"}</span></td>
  <td style="font-weight: 600; color: ${c.score >= 80 ? "#16a34a" : c.score >= 50 ? "#ca8a04" : "#dc2626"};">${c.score}%</td>
  <td style="font-size: 11px;">${c.toolsUsed.length > 0 ? c.toolsUsed.join(", ") : '<span style="color: #dc2626;">None</span>'}</td>
  <td>${c.findingsCount}</td>
</tr>`).join("")}
</table>

${report.owaspCoverage.categories.filter((c) => c.status === "not_tested" && c.gapAnalysis).length > 0 ? `
<h3>Coverage Gaps</h3>
${report.owaspCoverage.categories.filter((c) => c.status === "not_tested" && c.gapAnalysis).map((c) => `
<div style="border-left: 3px solid #ef4444; padding: 8px 16px; margin: 8px 0; background: #fef2f2; border-radius: 0 4px 4px 0;">
  <strong style="color: #991b1b;">${c.id}: ${c.name}</strong>
  <p style="font-size: 12px; margin-top: 4px;">${c.gapAnalysis}</p>
</div>`).join("")}
` : ""}

${report.owaspCoverage.recommendations.length > 0 ? `
<h3>OWASP Coverage Recommendations</h3>
<ol style="font-size: 13px;">
${report.owaspCoverage.recommendations.map((r) => `<li style="margin: 4px 0;">${r}</li>`).join("")}
</ol>` : ""}
` : ""}

${report.intelligenceGaps && report.intelligenceGaps.sections.length > 0 ? `
<!-- Intelligence Gaps -->
<h2>Intelligence Gaps Analysis</h2>
<p style="font-size: 13px; color: #64748b; margin-bottom: 16px;">${report.intelligenceGaps.summary}</p>
<table>
<tr><th>Category</th><th>Gap</th><th>Reason</th><th>Impact</th><th>Recommendation</th><th>Affected Assets</th></tr>
${report.intelligenceGaps.sections.flatMap((s) => s.gaps.map((g) => `<tr>
<td><strong>${s.categoryLabel}</strong></td>
<td>${g.title}</td>
<td>${g.reason}</td>
<td><span style="text-transform: uppercase; font-weight: 600; color: ${g.impact === "critical" ? "#dc2626" : g.impact === "high" ? "#ea580c" : g.impact === "medium" ? "#d97706" : "#65a30d"};">${g.impact}</span></td>
<td>${g.recommendation}</td>
<td>${g.assets.length > 0 ? g.assets.join(", ") : "N/A"}</td>
</tr>`)).join("")}
</table>
<p style="font-size: 12px; color: #94a3b8; margin-top: 8px;">Open: ${report.intelligenceGaps.totalOpen} | Resolved: ${report.intelligenceGaps.totalResolved}</p>
` : ""}

<!-- Recommendations -->
<h2>${complianceAuthorization ? report.toolEvidence?.length ? "11" : "10" : report.toolEvidence?.length ? "10" : "9"}. Recommendations</h2>
<ol class="rec-list">
  ${recommendations.map((r) => `<li>${r}</li>`).join("")}
</ol>

<!-- Conclusion -->
<h2>${complianceAuthorization ? "10" : "9"}. Conclusion</h2>
${conclusion.split("\n").filter(Boolean).map((p) => `<p>${p}</p>`).join("")}

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
export {
  generateReport,
  renderReportHTML
};
