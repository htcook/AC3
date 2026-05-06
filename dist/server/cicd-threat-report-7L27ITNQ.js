import "./chunk-KFQGP6VL.js";

// server/lib/cicd-threat-report.ts
function escapeHtml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
function severityColor(severity) {
  switch (severity?.toLowerCase()) {
    case "critical":
      return "#dc2626";
    case "high":
      return "#ea580c";
    case "medium":
      return "#d97706";
    case "low":
      return "#2563eb";
    case "info":
      return "#6b7280";
    default:
      return "#6b7280";
  }
}
function severityBg(severity) {
  switch (severity?.toLowerCase()) {
    case "critical":
      return "#fef2f2";
    case "high":
      return "#fff7ed";
    case "medium":
      return "#fffbeb";
    case "low":
      return "#eff6ff";
    case "info":
      return "#f9fafb";
    default:
      return "#f9fafb";
  }
}
function generateThreatReportHtml(data) {
  const tc = data.threatContext;
  const sr = data.scanResults;
  const now = (/* @__PURE__ */ new Date()).toISOString();
  const findingsRows = (tc?.enrichedFindings || sr.findings.map((f) => ({
    title: f.title,
    severity: f.severity,
    originalSeverity: f.severity,
    severityBoosted: false,
    boostReason: void 0,
    attributedGroups: [],
    riskTags: [],
    killChainPhases: []
  }))).slice(0, 50).map((f, i) => `
    <tr style="border-bottom: 1px solid #e5e7eb;">
      <td style="padding: 8px; font-size: 12px; color: #6b7280;">${i + 1}</td>
      <td style="padding: 8px; font-size: 12px; max-width: 300px; word-wrap: break-word;">${escapeHtml(f.title)}</td>
      <td style="padding: 8px;">
        <span style="background: ${severityBg(f.severity)}; color: ${severityColor(f.severity)}; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase;">${escapeHtml(f.severity)}</span>
        ${f.severityBoosted ? `<br/><span style="font-size: 10px; color: #d97706;">&#x2191; from ${f.originalSeverity}</span>` : ""}
      </td>
      <td style="padding: 8px; font-size: 11px; color: #374151;">
        ${f.attributedGroups.length > 0 ? f.attributedGroups.map((g) => `<span style="background: ${g.groupType === "apt" ? "#f3e8ff" : g.groupType === "ransomware" ? "#fef2f2" : "#fefce8"}; color: ${g.groupType === "apt" ? "#7c3aed" : g.groupType === "ransomware" ? "#dc2626" : "#ca8a04"}; padding: 1px 6px; border-radius: 3px; font-size: 10px; margin-right: 4px;">${escapeHtml(g.groupName)}</span>`).join("") : '<span style="color: #9ca3af; font-size: 10px;">None</span>'}
      </td>
      <td style="padding: 8px; font-size: 11px; color: #374151;">
        ${f.killChainPhases.length > 0 ? f.killChainPhases.join(", ") : "-"}
      </td>
      <td style="padding: 8px; font-size: 11px;">
        ${f.riskTags.map((t) => `<span style="background: ${t.includes("ransomware") ? "#fef2f2" : t.includes("apt") ? "#f3e8ff" : "#fefce8"}; color: ${t.includes("ransomware") ? "#dc2626" : t.includes("apt") ? "#7c3aed" : "#ca8a04"}; padding: 1px 5px; border-radius: 3px; font-size: 9px; margin-right: 2px;">${escapeHtml(t)}</span>`).join("") || "-"}
      </td>
    </tr>
  `).join("");
  const actorRows = (tc?.actorExposure || []).slice(0, 20).map((a, i) => `
    <tr style="border-bottom: 1px solid #e5e7eb;">
      <td style="padding: 6px 8px; font-size: 12px; color: #6b7280;">${i + 1}</td>
      <td style="padding: 6px 8px; font-size: 12px; font-weight: 600;">${escapeHtml(a.groupName)}</td>
      <td style="padding: 6px 8px;">
        <span style="background: ${a.groupType === "apt" ? "#f3e8ff" : a.groupType === "ransomware" ? "#fef2f2" : "#fefce8"}; color: ${a.groupType === "apt" ? "#7c3aed" : a.groupType === "ransomware" ? "#dc2626" : "#ca8a04"}; padding: 1px 6px; border-radius: 3px; font-size: 10px; text-transform: uppercase;">${escapeHtml(a.groupType)}</span>
      </td>
      <td style="padding: 6px 8px;">
        <span style="background: ${severityBg(a.threatLevel)}; color: ${severityColor(a.threatLevel)}; padding: 1px 6px; border-radius: 3px; font-size: 10px; text-transform: uppercase;">${escapeHtml(a.threatLevel)}</span>
      </td>
      <td style="padding: 6px 8px; font-size: 12px; text-align: center;">${a.findingCount}</td>
      <td style="padding: 6px 8px; font-size: 12px; text-align: center; font-weight: 600; color: ${a.exposureScore >= 60 ? "#dc2626" : a.exposureScore >= 30 ? "#d97706" : "#16a34a"};">${a.exposureScore}</td>
      <td style="padding: 6px 8px; font-size: 12px; text-align: center;">${a.active ? "&#x1f534;" : "&#x26aa;"}</td>
    </tr>
  `).join("");
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CI/CD Threat Assessment Report - Run #${data.runId}</title>
  <style>
    @media print {
      body { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
      .no-print { display: none !important; }
      .page-break { page-break-before: always; }
    }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 0; color: #111827; background: #fff; line-height: 1.5; }
    .container { max-width: 900px; margin: 0 auto; padding: 40px 32px; }
    h1 { font-size: 24px; margin: 0 0 4px; }
    h2 { font-size: 18px; margin: 32px 0 12px; padding-bottom: 8px; border-bottom: 2px solid #e5e7eb; }
    h3 { font-size: 14px; margin: 20px 0 8px; color: #374151; }
    table { width: 100%; border-collapse: collapse; margin: 12px 0; }
    th { background: #f9fafb; padding: 8px; text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: #6b7280; border-bottom: 2px solid #e5e7eb; }
    .stat-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 16px 0; }
    .stat-card { background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px; padding: 16px; text-align: center; }
    .stat-value { font-size: 28px; font-weight: 700; }
    .stat-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: #6b7280; margin-top: 4px; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
    .risk-banner { padding: 12px 16px; border-radius: 8px; margin: 12px 0; font-size: 13px; }
    .footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid #e5e7eb; font-size: 11px; color: #9ca3af; text-align: center; }
  </style>
</head>
<body>
  <div class="container">
    <!-- Header -->
    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 24px;">
      <div>
        <h1>CI/CD Threat Assessment Report</h1>
        <p style="color: #6b7280; font-size: 14px; margin: 4px 0;">Pipeline: <strong>${escapeHtml(data.pipelineName)}</strong> &mdash; Run #${data.runId}</p>
      </div>
      <div style="text-align: right;">
        <span class="badge" style="background: ${data.status === "passed" ? "#dcfce7" : data.status === "failed" ? "#fef2f2" : "#fefce8"}; color: ${data.status === "passed" ? "#16a34a" : data.status === "failed" ? "#dc2626" : "#d97706"}; font-size: 14px; padding: 4px 12px;">
          ${data.status.toUpperCase()}
        </span>
        ${data.gateEscalationReason ? '<br/><span style="font-size: 10px; color: #dc2626; margin-top: 4px; display: inline-block;">THREAT ESCALATED</span>' : ""}
      </div>
    </div>

    <!-- Metadata -->
    <table style="margin-bottom: 24px;">
      <tr style="border-bottom: 1px solid #e5e7eb;">
        <td style="padding: 6px 8px; font-size: 12px; color: #6b7280; width: 140px;">Branch</td>
        <td style="padding: 6px 8px; font-size: 12px;">${escapeHtml(data.branch || "N/A")}</td>
        <td style="padding: 6px 8px; font-size: 12px; color: #6b7280; width: 140px;">Commit</td>
        <td style="padding: 6px 8px; font-size: 12px; font-family: monospace;">${escapeHtml(data.commitSha?.substring(0, 7) || "N/A")}</td>
      </tr>
      <tr style="border-bottom: 1px solid #e5e7eb;">
        <td style="padding: 6px 8px; font-size: 12px; color: #6b7280;">Started</td>
        <td style="padding: 6px 8px; font-size: 12px;">${data.startedAt ? new Date(data.startedAt).toLocaleString() : "N/A"}</td>
        <td style="padding: 6px 8px; font-size: 12px; color: #6b7280;">Completed</td>
        <td style="padding: 6px 8px; font-size: 12px;">${data.completedAt ? new Date(data.completedAt).toLocaleString() : "N/A"}</td>
      </tr>
      <tr style="border-bottom: 1px solid #e5e7eb;">
        <td style="padding: 6px 8px; font-size: 12px; color: #6b7280;">Sector Context</td>
        <td style="padding: 6px 8px; font-size: 12px;">${escapeHtml(data.sectorContext || "Not configured")}</td>
        <td style="padding: 6px 8px; font-size: 12px; color: #6b7280;">Duration</td>
        <td style="padding: 6px 8px; font-size: 12px;">${sr.duration ? `${(sr.duration / 1e3).toFixed(1)}s` : "N/A"}</td>
      </tr>
    </table>

    <!-- Executive Summary -->
    <h2>Executive Summary</h2>
    <div class="stat-grid">
      <div class="stat-card">
        <div class="stat-value" style="color: #dc2626;">${sr.criticalCount}</div>
        <div class="stat-label">Critical</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" style="color: #ea580c;">${sr.highCount}</div>
        <div class="stat-label">High</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" style="color: #d97706;">${sr.mediumCount}</div>
        <div class="stat-label">Medium</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" style="color: #2563eb;">${sr.lowCount}</div>
        <div class="stat-label">Low</div>
      </div>
    </div>

    ${data.gateEscalationReason ? `
    <div class="risk-banner" style="background: #fef2f2; border: 1px solid #fecaca;">
      <strong style="color: #dc2626;">&#x26a0; Gate Escalation:</strong>
      <span style="color: #991b1b;">${escapeHtml(data.gateEscalationReason)}</span>
    </div>
    ` : ""}

    ${tc ? `
    <!-- Threat Intelligence Summary -->
    <h2>Threat Intelligence Summary</h2>
    <div class="stat-grid">
      <div class="stat-card">
        <div class="stat-value" style="color: ${tc.summary.actorExposureScore >= 60 ? "#dc2626" : tc.summary.actorExposureScore >= 30 ? "#d97706" : "#16a34a"};">${tc.summary.actorExposureScore}</div>
        <div class="stat-label">Exposure Score</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" style="color: #7c3aed;">${tc.summary.uniqueActorsMatched}</div>
        <div class="stat-label">Actors Matched</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" style="color: #d97706;">${tc.summary.severityBoostedCount}</div>
        <div class="stat-label">Severity Boosts</div>
      </div>
      <div class="stat-card">
        <div class="stat-value" style="color: #0891b2;">${tc.summary.killChainCoverage}%</div>
        <div class="stat-label">Kill Chain Coverage</div>
      </div>
    </div>

    ${tc.summary.ransomwareRiskFindings > 0 ? `
    <div class="risk-banner" style="background: #fef2f2; border: 1px solid #fecaca;">
      <strong style="color: #dc2626;">&#x1f6a8; Ransomware Risk:</strong>
      <span style="color: #991b1b;">${tc.summary.ransomwareRiskFindings} finding(s) linked to active ransomware groups</span>
    </div>
    ` : ""}

    ${tc.summary.aptRiskFindings > 0 ? `
    <div class="risk-banner" style="background: #f3e8ff; border: 1px solid #ddd6fe;">
      <strong style="color: #7c3aed;">&#x1f6e1; APT Risk:</strong>
      <span style="color: #5b21b6;">${tc.summary.aptRiskFindings} finding(s) linked to nation-state APT groups</span>
    </div>
    ` : ""}

    <!-- Actor Exposure Table -->
    ${tc.actorExposure.length > 0 ? `
    <h3>Threat Actor Exposure</h3>
    <table>
      <thead>
        <tr>
          <th>#</th>
          <th>Group Name</th>
          <th>Type</th>
          <th>Threat Level</th>
          <th style="text-align: center;">Findings</th>
          <th style="text-align: center;">Score</th>
          <th style="text-align: center;">Active</th>
        </tr>
      </thead>
      <tbody>${actorRows}</tbody>
    </table>
    ` : ""}
    ` : ""}

    <!-- Detailed Findings -->
    <div class="page-break"></div>
    <h2>Detailed Findings (${Math.min(50, sr.findings.length)} of ${sr.findings.length})</h2>
    <table>
      <thead>
        <tr>
          <th>#</th>
          <th>Finding</th>
          <th>Severity</th>
          <th>Attributed Groups</th>
          <th>Kill Chain</th>
          <th>Risk Tags</th>
        </tr>
      </thead>
      <tbody>${findingsRows}</tbody>
    </table>

    <!-- Footer -->
    <div class="footer">
      <p>Generated by Ace C3 &mdash; CI/CD Threat Intelligence Module</p>
      <p>Report generated: ${now} | Pipeline: ${escapeHtml(data.pipelineName)} | Run #${data.runId}</p>
    </div>

    <!-- Print Button (hidden in print) -->
    <div class="no-print" style="text-align: center; margin-top: 24px;">
      <button onclick="window.print()" style="background: #111827; color: white; padding: 10px 24px; border: none; border-radius: 6px; cursor: pointer; font-size: 14px;">
        Download as PDF (Print)
      </button>
    </div>
  </div>
</body>
</html>`;
}
export {
  generateThreatReportHtml
};
