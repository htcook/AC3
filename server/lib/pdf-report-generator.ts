/**
 * Branded PDF Report Generator for Ace C3 Patent Features
 * Generates HTML-based reports that can be rendered as PDF on the client side.
 * Uses AceofCloud branding with Harrison Cook attribution.
 */

export interface ReportSection {
  title: string;
  content: string; // HTML content
}

export interface ReportConfig {
  title: string;
  subtitle?: string;
  generatedAt: Date;
  sections: ReportSection[];
  classification?: "CONFIDENTIAL" | "INTERNAL" | "PUBLIC";
}

const BRAND_COLORS = {
  primary: "#1a1a1a",      // Near-black for headings
  accent: "#333333",       // Dark gray accent (minimal, no color)
  cream: "#ffffff",        // White background
  secondary: "#d9d9d9",    // Light gray for table headers
  danger: "#c00000",
  warning: "#b45309",
  success: "#15803d",
  muted: "#666666",
};

function escapeHtml(str: string): string {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

/**
 * Generate a complete branded HTML report suitable for client-side PDF rendering
 */
export function generateReportHtml(config: ReportConfig): string {
  const dateStr = config.generatedAt.toLocaleDateString("en-US", {
    year: "numeric", month: "long", day: "numeric", hour: "2-digit", minute: "2-digit",
  });
  const classification = config.classification || "CONFIDENTIAL";

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>${escapeHtml(config.title)}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Inter', Helvetica, Arial, sans-serif; color: #1a1a1a; line-height: 1.7; background: #fff; }
  .page { max-width: 850px; margin: 0 auto; padding: 48px 56px; }
  
  /* Header — Ace of Cloud minimal style: no logo, no decorative colors */
  .header { padding-bottom: 28px; margin-bottom: 36px; border-bottom: 1px solid #cccccc; }
  .report-title { font-size: 28px; font-weight: 700; color: #1a1a1a; margin-bottom: 16px; }
  .report-subtitle { font-size: 14px; color: #666666; margin-bottom: 12px; }
  .report-meta { font-size: 12px; color: #666666; line-height: 1.8; }
  .report-meta div { margin-bottom: 2px; }
  .classification-line { font-weight: 700; font-size: 13px; margin-top: 12px; }
  
  /* Sections */
  .section { margin-bottom: 32px; page-break-inside: avoid; }
  .section-title { font-size: 20px; font-weight: 700; color: #1a1a1a; margin-bottom: 16px; padding-bottom: 4px; }
  .section-content { font-size: 13px; line-height: 1.7; }
  .section-content p { margin-bottom: 10px; }
  
  /* Tables — Ace of Cloud style: light gray headers, thin borders, no alternating rows */
  table { width: 100%; border-collapse: collapse; margin: 14px 0; font-size: 12px; }
  th { background: #d9d9d9; color: #1a1a1a; padding: 8px 12px; text-align: left; font-weight: 600; font-size: 11px; border: 1px solid #999999; }
  td { padding: 8px 12px; border: 1px solid #cccccc; }
  
  /* Status badges — muted, professional */
  .badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: 600; }
  .badge-critical { background: #f5d5d5; color: #c00000; }
  .badge-high { background: #fde8d0; color: #b45309; }
  .badge-medium { background: #fef3c7; color: #92400e; }
  .badge-low { background: #d1fae5; color: #15803d; }
  .badge-info { background: #dbeafe; color: #1d4ed8; }
  .badge-fixed { background: #d1fae5; color: #15803d; }
  .badge-vulnerable { background: #f5d5d5; color: #c00000; }
  .badge-pending { background: #fef3c7; color: #92400e; }
  .badge-overdue { background: #f5d5d5; color: #c00000; border: 1px solid #e8a0a0; }
  
  /* Stats grid */
  .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 16px 0; }
  .stat-card { background: #f5f5f5; border: 1px solid #d9d9d9; border-radius: 4px; padding: 12px; text-align: center; }
  .stat-value { font-size: 24px; font-weight: 700; color: #1a1a1a; }
  .stat-label { font-size: 11px; color: #666666; text-transform: uppercase; letter-spacing: 0.5px; }
  
  /* Kill chain */
  .kill-chain { display: flex; gap: 4px; margin: 12px 0; flex-wrap: wrap; }
  .kill-chain-step { background: #333333; color: #fff; padding: 6px 12px; border-radius: 3px; font-size: 11px; font-weight: 500; position: relative; }
  .kill-chain-step::after { content: '\u2192'; position: absolute; right: -10px; top: 50%; transform: translateY(-50%); color: #999; font-size: 14px; }
  .kill-chain-step:last-child::after { display: none; }
  
  /* Footer */
  .footer { border-top: 1px solid #cccccc; padding-top: 16px; margin-top: 40px; font-size: 11px; color: #666666; display: flex; justify-content: space-between; }
  
  /* Confidence bar */
  .confidence-bar { height: 8px; background: #e5e5e5; border-radius: 4px; overflow: hidden; width: 100px; display: inline-block; vertical-align: middle; }
  .confidence-fill { height: 100%; border-radius: 4px; }
  .confidence-high { background: ${BRAND_COLORS.success}; }
  .confidence-medium { background: ${BRAND_COLORS.warning}; }
  .confidence-low { background: ${BRAND_COLORS.danger}; }
  
  @media print {
    .page { padding: 24px; max-width: 100%; }
    .section { page-break-inside: avoid; }
    .section-title { page-break-after: avoid; }
  }
</style>
</head>
<body>
<div class="page">
  <div class="header">
    <div class="report-title">${escapeHtml(config.title)}</div>
    ${config.subtitle ? `<div class="report-subtitle">${escapeHtml(config.subtitle)}</div>` : ""}
    <div class="report-meta">
      <div>Prepared by: Ace of Cloud LLC</div>
      <div>Report Date: ${dateStr}</div>
      <div>Platform: Ace C3 (Cyber Campaign Command)</div>
    </div>
    <div class="classification-line">${classification} \u2013 Security Assessment Report</div>
  </div>
  
  ${config.sections.map(s => `
  <div class="section">
    <div class="section-title">${escapeHtml(s.title)}</div>
    <div class="section-content">${s.content}</div>
  </div>
  `).join("")}
  
  <div class="footer">
    <div>Ace of Cloud LLC \u2014 aceofcloud.com</div>
    <div>${classification} \u2014 ${dateStr}</div>
  </div>
</div>
</body>
</html>`;
}

// ─── Attack Planner Report ──────────────────────────────────────────────────

export function generateAttackPlanReport(plan: any): string {
  const phases = plan.phases || [];
  const sections: ReportSection[] = [];

  // Executive Summary
  sections.push({
    title: "Executive Summary",
    content: `<p>${escapeHtml(plan.summary || "AI-generated attack plan based on MITRE ATT&CK framework.")}</p>
    <div class="stats-grid">
      <div class="stat-card"><div class="stat-value">${phases.length}</div><div class="stat-label">Kill Chain Phases</div></div>
      <div class="stat-card"><div class="stat-value">${plan.totalSteps || 0}</div><div class="stat-label">Attack Steps</div></div>
      <div class="stat-card"><div class="stat-value">${plan.estimatedRiskScore || "N/A"}/10</div><div class="stat-label">Risk Score</div></div>
      <div class="stat-card"><div class="stat-value">${escapeHtml(plan.estimatedDuration || "N/A")}</div><div class="stat-label">Est. Duration</div></div>
    </div>
    <p><strong>Threat Actor Emulated:</strong> ${escapeHtml(plan.threatActorEmulated || "Generic APT")}</p>`,
  });

  // Kill Chain Overview
  if (phases.length > 0) {
    const chainHtml = phases.map((p: any) =>
      `<span class="kill-chain-step">${escapeHtml(p.name || "Phase")}</span>`
    ).join("");
    sections.push({
      title: "Kill Chain Overview",
      content: `<div class="kill-chain">${chainHtml}</div>`,
    });
  }

  // Detailed Phases
  for (let i = 0; i < phases.length; i++) {
    const phase = phases[i];
    const stepsHtml = (phase.steps || []).map((step: any) =>
      `<tr>
        <td><strong>${escapeHtml(step.techniqueId || step.technique_id || "—")}</strong></td>
        <td>${escapeHtml(step.name || step.technique || "—")}</td>
        <td>${escapeHtml(step.description || "—")}</td>
        <td><span class="badge badge-${step.detectionRisk === "high" ? "critical" : step.detectionRisk === "medium" ? "medium" : "low"}">${escapeHtml(step.detectionRisk || "—")}</span></td>
      </tr>`
    ).join("");

    sections.push({
      title: `Phase ${i + 1}: ${phase.name || "Unnamed Phase"}`,
      content: `<p><strong>Objective:</strong> ${escapeHtml(phase.objective || "—")}</p>
      ${stepsHtml ? `<table><thead><tr><th>Technique ID</th><th>Name</th><th>Description</th><th>Detection Risk</th></tr></thead><tbody>${stepsHtml}</tbody></table>` : "<p>No detailed steps available.</p>"}`,
    });
  }

  // Detection Opportunities
  if (plan.detectionOpportunities?.length) {
    sections.push({
      title: "Detection Opportunities",
      content: `<ul>${plan.detectionOpportunities.map((d: string) => `<li>${escapeHtml(d)}</li>`).join("")}</ul>`,
    });
  }

  // Recommendations
  if (plan.recommendations?.length) {
    sections.push({
      title: "Defensive Recommendations",
      content: `<ul>${plan.recommendations.map((r: string) => `<li>${escapeHtml(r)}</li>`).join("")}</ul>`,
    });
  }

  return generateReportHtml({
    title: "Attack Plan Report",
    subtitle: plan.name || "AI-Generated Attack Simulation Plan",
    generatedAt: new Date(),
    sections,
    classification: "CONFIDENTIAL",
  });
}

// ─── Remediation Dashboard Report ───────────────────────────────────────────

export function generateRemediationReport(stats: any, items: any[], overdueItems: any[]): string {
  const sections: ReportSection[] = [];

  // Executive Summary
  sections.push({
    title: "Executive Summary",
    content: `<div class="stats-grid">
      <div class="stat-card"><div class="stat-value">${stats.total}</div><div class="stat-label">Total Findings</div></div>
      <div class="stat-card"><div class="stat-value">${stats.verifiedFixed}</div><div class="stat-label">Verified Fixed</div></div>
      <div class="stat-card"><div class="stat-value" style="color:${BRAND_COLORS.danger}">${stats.stillVulnerable}</div><div class="stat-label">Still Vulnerable</div></div>
      <div class="stat-card"><div class="stat-value">${stats.slaCompliant}%</div><div class="stat-label">SLA Compliance</div></div>
    </div>
    <p><strong>Mean Time to Remediate:</strong> ${stats.avgRemediationHours} hours</p>
    <p><strong>Overdue Items:</strong> ${stats.overdue} findings past SLA deadline</p>`,
  });

  // Severity Breakdown
  const sb = stats.severityBreakdown || {};
  sections.push({
    title: "Severity Breakdown",
    content: `<table>
      <thead><tr><th>Severity</th><th>Count</th><th>Percentage</th></tr></thead>
      <tbody>
        <tr><td><span class="badge badge-critical">CRITICAL</span></td><td>${sb.critical || 0}</td><td>${stats.total ? Math.round(((sb.critical || 0) / stats.total) * 100) : 0}%</td></tr>
        <tr><td><span class="badge badge-high">HIGH</span></td><td>${sb.high || 0}</td><td>${stats.total ? Math.round(((sb.high || 0) / stats.total) * 100) : 0}%</td></tr>
        <tr><td><span class="badge badge-medium">MEDIUM</span></td><td>${sb.medium || 0}</td><td>${stats.total ? Math.round(((sb.medium || 0) / stats.total) * 100) : 0}%</td></tr>
        <tr><td><span class="badge badge-low">LOW</span></td><td>${sb.low || 0}</td><td>${stats.total ? Math.round(((sb.low || 0) / stats.total) * 100) : 0}%</td></tr>
        <tr><td><span class="badge badge-info">INFO</span></td><td>${sb.info || 0}</td><td>${stats.total ? Math.round(((sb.info || 0) / stats.total) * 100) : 0}%</td></tr>
      </tbody>
    </table>`,
  });

  // Overdue Items (Critical Attention)
  if (overdueItems.length > 0) {
    const overdueRows = overdueItems.map((item: any) =>
      `<tr>
        <td><span class="badge badge-${item.severity || "medium"}">${(item.severity || "MEDIUM").toUpperCase()}</span></td>
        <td>${escapeHtml(item.findingTitle || "—")}</td>
        <td>${escapeHtml(item.assetName || "—")}</td>
        <td><span class="badge badge-overdue">${item.hoursOverdue || 0}h overdue</span></td>
      </tr>`
    ).join("");
    sections.push({
      title: "Overdue Items — Requires Immediate Attention",
      content: `<table>
        <thead><tr><th>Severity</th><th>Finding</th><th>Asset</th><th>SLA Status</th></tr></thead>
        <tbody>${overdueRows}</tbody>
      </table>`,
    });
  }

  // All Findings
  if (items.length > 0) {
    const rows = items.slice(0, 50).map((item: any) => {
      const statusClass = item.status === "verified_fixed" ? "fixed" : item.status === "still_vulnerable" ? "vulnerable" : "pending";
      return `<tr>
        <td><span class="badge badge-${item.severity || "medium"}">${(item.severity || "—").toUpperCase()}</span></td>
        <td>${escapeHtml(item.findingTitle || "—")}</td>
        <td>${escapeHtml(item.assetName || "—")}</td>
        <td><span class="badge badge-${statusClass}">${(item.status || "—").replace(/_/g, " ")}</span></td>
        <td>${escapeHtml(item.verificationMethod || "—")}</td>
      </tr>`;
    }).join("");
    sections.push({
      title: "All Findings",
      content: `<table>
        <thead><tr><th>Severity</th><th>Finding</th><th>Asset</th><th>Status</th><th>Method</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
      ${items.length > 50 ? `<p style="color:${BRAND_COLORS.muted};font-size:11px;">Showing 50 of ${items.length} findings.</p>` : ""}`,
    });
  }

  return generateReportHtml({
    title: "Remediation Verification Report",
    subtitle: "SLA Compliance & Vulnerability Remediation Status",
    generatedAt: new Date(),
    sections,
    classification: "CONFIDENTIAL",
  });
}

// ─── Corroboration Engine Report ────────────────────────────────────────────

export function generateCorroborationReport(report: any): string {
  const sections: ReportSection[] = [];

  // Executive Summary
  sections.push({
    title: "Executive Summary",
    content: `<div class="stats-grid">
      <div class="stat-card"><div class="stat-value">${report.totalFindings || 0}</div><div class="stat-label">Total Findings</div></div>
      <div class="stat-card"><div class="stat-value">${report.corroboratedFindings || 0}</div><div class="stat-label">Corroborated</div></div>
      <div class="stat-card"><div class="stat-value">${report.contradictions || 0}</div><div class="stat-label">Contradictions</div></div>
      <div class="stat-card"><div class="stat-value">${report.estimatedFalsePositiveReduction || 0}%</div><div class="stat-label">FP Reduction</div></div>
    </div>
    <p><strong>Analysis:</strong> Cross-source corroboration analyzed ${report.totalFindings || 0} findings across ${report.sourcesQueried || 0} intelligence sources. An estimated ${report.estimatedFalsePositiveReduction || 0}% false positive reduction was achieved through multi-source validation.</p>`,
  });

  // Corroboration Results
  if (report.results?.length) {
    const rows = report.results.map((r: any) => {
      const conf = r.adjustedConfidence || r.originalConfidence || 0;
      const confClass = conf >= 0.7 ? "high" : conf >= 0.4 ? "medium" : "low";
      const confPct = Math.round(conf * 100);
      return `<tr>
        <td>${escapeHtml(r.host || r.finding?.host || "—")}</td>
        <td>${escapeHtml(r.finding?.title || r.title || "—")}</td>
        <td>${r.sourcesConfirming || 0} / ${r.sourcesQueried || 0}</td>
        <td>
          <div class="confidence-bar"><div class="confidence-fill confidence-${confClass}" style="width:${confPct}%"></div></div>
          ${confPct}%
        </td>
        <td><span class="badge badge-${r.verdict === "confirmed" ? "fixed" : r.verdict === "contradicted" ? "vulnerable" : "pending"}">${escapeHtml(r.verdict || "unverified")}</span></td>
      </tr>`;
    }).join("");
    sections.push({
      title: "Finding Corroboration Details",
      content: `<table>
        <thead><tr><th>Host</th><th>Finding</th><th>Sources</th><th>Confidence</th><th>Verdict</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>`,
    });
  }

  return generateReportHtml({
    title: "Cross-Source Corroboration Report",
    subtitle: "Multi-Source Intelligence Validation & False Positive Analysis",
    generatedAt: new Date(),
    sections,
    classification: "CONFIDENTIAL",
  });
}
