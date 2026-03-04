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
  primary: "#213555",      // Ace of Cloud navy blue (from aceofcloud.com)
  accent: "#14b8a6",       // Teal accent
  cream: "#F5EFE7",        // Warm cream background
  secondary: "#D8C4B6",    // Warm tan/beige
  danger: "#ef4444",
  warning: "#f59e0b",
  success: "#22c55e",
  muted: "#64748b",
};

const BRAND_LOGO_URL = "https://d2xsxph8kpxj0f.cloudfront.net/310419663028432609/VmWWcXQYZJYuALRdNNvsC2/ace_of_cloud_logo_8934407a.jpeg";

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
  body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; color: #1e293b; line-height: 1.6; background: #fff; }
  .page { max-width: 800px; margin: 0 auto; padding: 40px; }
  
  /* Header */
  .header { border-bottom: 3px solid ${BRAND_COLORS.accent}; padding-bottom: 24px; margin-bottom: 32px; }
  .header-top { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 16px; }
  .brand { display: flex; align-items: center; gap: 12px; }
  .brand-logo { width: 48px; height: 48px; border-radius: 8px; overflow: hidden; }
  .brand-logo img { width: 100%; height: 100%; object-fit: contain; }
  .brand-name { font-size: 20px; font-weight: 700; color: ${BRAND_COLORS.primary}; }
  .brand-sub { font-size: 11px; color: ${BRAND_COLORS.muted}; text-transform: uppercase; letter-spacing: 1px; }
  .classification { background: ${BRAND_COLORS.primary}; color: #fff; padding: 4px 12px; border-radius: 4px; font-size: 10px; font-weight: 600; letter-spacing: 1px; text-transform: uppercase; }
  .report-title { font-size: 28px; font-weight: 700; color: ${BRAND_COLORS.primary}; margin-bottom: 4px; }
  .report-subtitle { font-size: 14px; color: ${BRAND_COLORS.muted}; }
  .report-meta { display: flex; gap: 24px; margin-top: 12px; font-size: 12px; color: ${BRAND_COLORS.muted}; }
  .report-meta span { display: flex; align-items: center; gap: 4px; }
  
  /* Sections */
  .section { margin-bottom: 28px; page-break-inside: avoid; }
  .section-title { font-size: 18px; font-weight: 700; color: ${BRAND_COLORS.primary}; border-left: 4px solid ${BRAND_COLORS.accent}; padding-left: 12px; margin-bottom: 16px; }
  .section-content { font-size: 13px; }
  
  /* Tables */
  table { width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 12px; }
  th { background: ${BRAND_COLORS.primary}; color: #fff; padding: 8px 12px; text-align: left; font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }
  td { padding: 8px 12px; border-bottom: 1px solid #e2e8f0; }
  tr:nth-child(even) { background: #f8fafc; }
  
  /* Status badges */
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
  .badge-critical { background: #fef2f2; color: #dc2626; }
  .badge-high { background: #fff7ed; color: #ea580c; }
  .badge-medium { background: #fefce8; color: #ca8a04; }
  .badge-low { background: #f0fdf4; color: #16a34a; }
  .badge-info { background: #eff6ff; color: #2563eb; }
  .badge-fixed { background: #f0fdf4; color: #16a34a; }
  .badge-vulnerable { background: #fef2f2; color: #dc2626; }
  .badge-pending { background: #fefce8; color: #ca8a04; }
  .badge-overdue { background: #fef2f2; color: #dc2626; border: 1px solid #fca5a5; }
  
  /* Stats grid */
  .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 16px 0; }
  .stat-card { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px; text-align: center; }
  .stat-value { font-size: 24px; font-weight: 700; color: ${BRAND_COLORS.primary}; }
  .stat-label { font-size: 11px; color: ${BRAND_COLORS.muted}; text-transform: uppercase; letter-spacing: 0.5px; }
  
  /* Kill chain */
  .kill-chain { display: flex; gap: 4px; margin: 12px 0; flex-wrap: wrap; }
  .kill-chain-step { background: ${BRAND_COLORS.primary}; color: #fff; padding: 6px 12px; border-radius: 4px; font-size: 11px; font-weight: 500; position: relative; }
  .kill-chain-step::after { content: '→'; position: absolute; right: -10px; top: 50%; transform: translateY(-50%); color: ${BRAND_COLORS.muted}; font-size: 14px; }
  .kill-chain-step:last-child::after { display: none; }
  
  /* Footer */
  .footer { border-top: 2px solid #e2e8f0; padding-top: 16px; margin-top: 40px; font-size: 11px; color: ${BRAND_COLORS.muted}; display: flex; justify-content: space-between; }
  
  /* Confidence bar */
  .confidence-bar { height: 8px; background: #e2e8f0; border-radius: 4px; overflow: hidden; width: 100px; display: inline-block; vertical-align: middle; }
  .confidence-fill { height: 100%; border-radius: 4px; }
  .confidence-high { background: ${BRAND_COLORS.success}; }
  .confidence-medium { background: ${BRAND_COLORS.warning}; }
  .confidence-low { background: ${BRAND_COLORS.danger}; }
  
  @media print {
    .page { padding: 20px; }
    .section { page-break-inside: avoid; }
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
      <div class="classification">${classification}</div>
    </div>
    <div class="report-title">${escapeHtml(config.title)}</div>
    ${config.subtitle ? `<div class="report-subtitle">${escapeHtml(config.subtitle)}</div>` : ""}
    <div class="report-meta">
      <span>Generated: ${dateStr}</span>
      <span>Prepared by: Ace of Cloud LLC</span>
      <span>Platform: Ace C3</span>
      <span>aceofcloud.com</span>
    </div>
  </div>
  
  ${config.sections.map(s => `
  <div class="section">
    <div class="section-title">${escapeHtml(s.title)}</div>
    <div class="section-content">${s.content}</div>
  </div>
  `).join("")}
  
  <div class="footer">
    <div>Ace of Cloud LLC — Ace C3 Platform | aceofcloud.com</div>
    <div>${classification} — ${dateStr}</div>
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
