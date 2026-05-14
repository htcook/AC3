import "./chunk-KFQGP6VL.js";

// server/lib/zap-report-generator.ts
var THEME = {
  bg: "#0A0E14",
  bgCard: "#111820",
  bgCardHover: "#1A2332",
  fg: "#FFFFFF",
  fgMuted: "#8B9BB4",
  accent: "#00E5CC",
  accentDim: "rgba(0, 229, 204, 0.15)",
  danger: "#FF4444",
  dangerDim: "rgba(255, 68, 68, 0.15)",
  warning: "#FFAA00",
  warningDim: "rgba(255, 170, 0, 0.15)",
  success: "#00CC66",
  successDim: "rgba(0, 204, 102, 0.15)",
  info: "#3B82F6",
  infoDim: "rgba(59, 130, 246, 0.15)",
  border: "#1E2A3A",
  borderAccent: "#00E5CC",
  fontPrimary: "'Inter', -apple-system, BlinkMacSystemFont, sans-serif",
  fontMono: "'JetBrains Mono', 'Fira Code', monospace"
};
var SEVERITY_COLORS = {
  critical: { bg: THEME.dangerDim, text: THEME.danger, border: THEME.danger },
  high: { bg: THEME.dangerDim, text: THEME.danger, border: THEME.danger },
  medium: { bg: THEME.warningDim, text: THEME.warning, border: THEME.warning },
  low: { bg: THEME.infoDim, text: THEME.info, border: THEME.info },
  info: { bg: "rgba(139, 155, 180, 0.1)", text: THEME.fgMuted, border: THEME.border }
};
var OWASP_TOP_10 = [
  { id: "A01", name: "Broken Access Control", cwes: [22, 23, 35, 59, 200, 201, 219, 264, 275, 276, 284, 285, 352, 359, 377, 402, 425, 441, 497, 538, 540, 548, 552, 566, 601, 639, 651, 668, 706, 862, 863, 913, 922, 1275] },
  { id: "A02", name: "Cryptographic Failures", cwes: [261, 296, 310, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 335, 336, 337, 338, 340, 347, 523, 720, 757, 759, 760, 780, 818, 916] },
  { id: "A03", name: "Injection", cwes: [20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 100, 113, 116, 138, 184, 470, 471, 564, 610, 643, 644, 652, 917] },
  { id: "A04", name: "Insecure Design", cwes: [73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311, 312, 313, 316, 419, 430, 434, 444, 451, 472, 501, 522, 525, 539, 579, 598, 602, 642, 646, 650, 653, 656, 657, 799, 807, 840, 841, 927, 1021, 1173] },
  { id: "A05", name: "Security Misconfiguration", cwes: [2, 11, 13, 15, 16, 388, 489, 497, 524, 614, 756, 942, 1004, 1032, 1174] },
  { id: "A06", name: "Vulnerable & Outdated Components", cwes: [937, 1035, 1104] },
  { id: "A07", name: "Identification & Authentication Failures", cwes: [255, 259, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307, 346, 384, 521, 613, 620, 640, 798, 940, 1216] },
  { id: "A08", name: "Software & Data Integrity Failures", cwes: [345, 353, 426, 494, 502, 565, 784, 829, 830, 915] },
  { id: "A09", name: "Security Logging & Monitoring Failures", cwes: [117, 223, 532, 778] },
  { id: "A10", name: "Server-Side Request Forgery", cwes: [918] }
];
function generateThemedReport(data) {
  const sections = [];
  sections.push(renderExecutiveSummary(data));
  sections.push(renderRiskScoreCard(data));
  const owaspData = data.owaspMapping || generateOwaspMapping(data.findings);
  sections.push(renderOwaspCompliance(owaspData));
  if (data.mitreMapping.length > 0) {
    sections.push(renderMitreMapping(data.mitreMapping));
  }
  if (data.wafDetection) {
    sections.push(renderWafDetection(data.wafDetection));
  }
  if (data.credentialResults) {
    sections.push(renderCredentialResults(data.credentialResults));
  }
  if (data.reportType === "technical" || data.reportType === "full") {
    sections.push(renderFindingsDetail(data.findings));
  }
  sections.push(renderRemediationPriorities(data.findings));
  return wrapInHtmlDocument(data, sections.join("\n"));
}
function generateOwaspMapping(findings) {
  return OWASP_TOP_10.map((category) => {
    const matchedFindings = findings.filter(
      (f) => f.cweId && category.cwes.includes(f.cweId)
    );
    return {
      category: category.name,
      categoryId: category.id,
      status: matchedFindings.length === 0 ? "pass" : matchedFindings.some((f) => f.severity === "high" || f.severity === "critical") ? "fail" : "partial",
      findingCount: matchedFindings.length,
      findings: matchedFindings.map((f) => f.alertName)
    };
  });
}
function renderExecutiveSummary(data) {
  const riskLevel = data.alertCounts.critical > 0 || data.alertCounts.high > 2 ? "CRITICAL" : data.alertCounts.high > 0 ? "HIGH" : data.alertCounts.medium > 3 ? "MEDIUM" : "LOW";
  const riskColor = riskLevel === "CRITICAL" ? THEME.danger : riskLevel === "HIGH" ? THEME.danger : riskLevel === "MEDIUM" ? THEME.warning : THEME.success;
  return `
    <div class="section">
      <h2 class="section-title">EXECUTIVE SUMMARY</h2>
      <div class="summary-grid">
        <div class="summary-card risk-card" style="border-left: 4px solid ${riskColor};">
          <div class="summary-label">Overall Risk Level</div>
          <div class="summary-value" style="color: ${riskColor}; font-size: 28px;">${riskLevel}</div>
        </div>
        <div class="summary-card">
          <div class="summary-label">Target</div>
          <div class="summary-value mono">${escapeHtml(data.scan.targetUrl)}</div>
        </div>
        <div class="summary-card">
          <div class="summary-label">Scan Mode</div>
          <div class="summary-value">${data.scan.scanMode.toUpperCase()} ${data.scan.scanType.toUpperCase()}</div>
        </div>
        <div class="summary-card">
          <div class="summary-label">Duration</div>
          <div class="summary-value">${data.scan.duration}</div>
        </div>
      </div>

      <div class="alert-summary">
        <div class="alert-bar">
          ${data.alertCounts.critical > 0 ? `<div class="alert-segment" style="flex: ${data.alertCounts.critical}; background: ${THEME.danger};" title="Critical: ${data.alertCounts.critical}"></div>` : ""}
          ${data.alertCounts.high > 0 ? `<div class="alert-segment" style="flex: ${data.alertCounts.high}; background: ${THEME.danger}; opacity: 0.8;" title="High: ${data.alertCounts.high}"></div>` : ""}
          ${data.alertCounts.medium > 0 ? `<div class="alert-segment" style="flex: ${data.alertCounts.medium}; background: ${THEME.warning};" title="Medium: ${data.alertCounts.medium}"></div>` : ""}
          ${data.alertCounts.low > 0 ? `<div class="alert-segment" style="flex: ${data.alertCounts.low}; background: ${THEME.info};" title="Low: ${data.alertCounts.low}"></div>` : ""}
          ${data.alertCounts.info > 0 ? `<div class="alert-segment" style="flex: ${data.alertCounts.info}; background: ${THEME.fgMuted}; opacity: 0.4;" title="Info: ${data.alertCounts.info}"></div>` : ""}
        </div>
        <div class="alert-counts">
          <span class="alert-count" style="color: ${THEME.danger};">\u25A0 Critical: ${data.alertCounts.critical}</span>
          <span class="alert-count" style="color: ${THEME.danger}; opacity: 0.8;">\u25A0 High: ${data.alertCounts.high}</span>
          <span class="alert-count" style="color: ${THEME.warning};">\u25A0 Medium: ${data.alertCounts.medium}</span>
          <span class="alert-count" style="color: ${THEME.info};">\u25A0 Low: ${data.alertCounts.low}</span>
          <span class="alert-count" style="color: ${THEME.fgMuted};">\u25A0 Info: ${data.alertCounts.info}</span>
        </div>
      </div>

      ${data.scan.techStack.length > 0 ? `
        <div class="tech-stack">
          <div class="summary-label" style="margin-bottom: 8px;">Detected Technology Stack</div>
          <div class="tech-tags">
            ${data.scan.techStack.map((t) => `<span class="tech-tag">${escapeHtml(t)}</span>`).join("")}
          </div>
        </div>
      ` : ""}

      <div class="scan-meta">
        <table class="meta-table">
          <tr><td class="meta-label">Scan Name</td><td class="meta-value">${escapeHtml(data.scan.scanName)}</td></tr>
          <tr><td class="meta-label">Started</td><td class="meta-value">${data.scan.startedAt}</td></tr>
          <tr><td class="meta-label">Completed</td><td class="meta-value">${data.scan.completedAt}</td></tr>
          <tr><td class="meta-label">URLs Discovered</td><td class="meta-value">${data.scan.urlsDiscovered}</td></tr>
          <tr><td class="meta-label">Total Findings</td><td class="meta-value">${data.alertCounts.total}</td></tr>
          ${data.scan.attackChainId ? `<tr><td class="meta-label">Attack Chain</td><td class="meta-value mono">${data.scan.attackChainId}</td></tr>` : ""}
        </table>
      </div>
    </div>`;
}
function renderRiskScoreCard(data) {
  const score = Math.min(100, Math.round(
    data.alertCounts.critical * 25 + data.alertCounts.high * 15 + data.alertCounts.medium * 5 + data.alertCounts.low * 1
  ));
  const exploitableCount = data.findings.filter((f) => f.exploitAvailable).length;
  const aiTriagedCount = data.findings.filter((f) => f.aiTriageVerdict).length;
  const confirmedCount = data.findings.filter((f) => f.aiTriageVerdict === "true_positive").length;
  return `
    <div class="section">
      <h2 class="section-title">RISK ASSESSMENT</h2>
      <div class="risk-grid">
        <div class="risk-score-card">
          <div class="risk-score-circle" style="--score: ${score}; --color: ${score > 70 ? THEME.danger : score > 40 ? THEME.warning : THEME.success};">
            <span class="risk-score-number">${score}</span>
            <span class="risk-score-label">/ 100</span>
          </div>
          <div class="risk-score-desc">Weighted Risk Score</div>
        </div>
        <div class="risk-metrics">
          <div class="risk-metric">
            <span class="risk-metric-value" style="color: ${THEME.danger};">${exploitableCount}</span>
            <span class="risk-metric-label">Exploitable Findings</span>
          </div>
          <div class="risk-metric">
            <span class="risk-metric-value" style="color: ${THEME.accent};">${aiTriagedCount}</span>
            <span class="risk-metric-label">AI Triaged</span>
          </div>
          <div class="risk-metric">
            <span class="risk-metric-value" style="color: ${THEME.warning};">${confirmedCount}</span>
            <span class="risk-metric-label">Confirmed True Positives</span>
          </div>
          <div class="risk-metric">
            <span class="risk-metric-value" style="color: ${THEME.info};">${data.mitreMapping.length}</span>
            <span class="risk-metric-label">MITRE Techniques</span>
          </div>
        </div>
      </div>
    </div>`;
}
function renderOwaspCompliance(mapping) {
  const passCount = mapping.filter((m) => m.status === "pass").length;
  const failCount = mapping.filter((m) => m.status === "fail").length;
  return `
    <div class="section">
      <h2 class="section-title">OWASP TOP 10 \u2014 2021 COMPLIANCE</h2>
      <div class="owasp-summary">
        <span style="color: ${THEME.success};">\u2713 ${passCount} Pass</span>
        <span style="color: ${THEME.danger};">\u2717 ${failCount} Fail</span>
        <span style="color: ${THEME.warning};">\u25D0 ${mapping.length - passCount - failCount} Partial</span>
      </div>
      <table class="data-table">
        <thead>
          <tr>
            <th>Category</th>
            <th>Status</th>
            <th>Findings</th>
            <th>Details</th>
          </tr>
        </thead>
        <tbody>
          ${mapping.map((m) => {
    const statusIcon = m.status === "pass" ? `<span style="color: ${THEME.success};">\u2713 PASS</span>` : m.status === "fail" ? `<span style="color: ${THEME.danger};">\u2717 FAIL</span>` : `<span style="color: ${THEME.warning};">\u25D0 PARTIAL</span>`;
    return `
              <tr>
                <td><strong>${m.categoryId}</strong> ${escapeHtml(m.category)}</td>
                <td>${statusIcon}</td>
                <td>${m.findingCount}</td>
                <td class="findings-list">${m.findings.slice(0, 3).map((f) => escapeHtml(f)).join(", ") || "\u2014"}</td>
              </tr>`;
  }).join("")}
        </tbody>
      </table>
    </div>`;
}
function renderMitreMapping(mapping) {
  const byTactic = /* @__PURE__ */ new Map();
  for (const m of mapping) {
    if (!byTactic.has(m.tactic)) byTactic.set(m.tactic, []);
    byTactic.get(m.tactic).push(m);
  }
  return `
    <div class="section">
      <h2 class="section-title">MITRE ATT&CK MAPPING</h2>
      <div class="mitre-grid">
        ${Array.from(byTactic.entries()).map(([tactic, techniques]) => `
          <div class="mitre-tactic">
            <div class="mitre-tactic-header">${escapeHtml(tactic)}</div>
            ${techniques.map((t) => `
              <div class="mitre-technique">
                <span class="mitre-id">${t.techniqueId}</span>
                <span class="mitre-name">${escapeHtml(t.techniqueName)}</span>
                <span class="mitre-count">${t.findingCount}</span>
              </div>
            `).join("")}
          </div>
        `).join("")}
      </div>
    </div>`;
}
function renderWafDetection(waf) {
  return `
    <div class="section">
      <h2 class="section-title">WAF / NGFW DETECTION</h2>
      <div class="waf-card" style="border-left: 4px solid ${waf.detected ? THEME.warning : THEME.success};">
        <div class="waf-status">
          ${waf.detected ? `<span style="color: ${THEME.warning};">\u26A0 WAF DETECTED</span>` : `<span style="color: ${THEME.success};">\u2713 No WAF Detected</span>`}
        </div>
        ${waf.detected ? `
          <table class="meta-table">
            <tr><td class="meta-label">Vendor</td><td class="meta-value">${escapeHtml(waf.vendor)}</td></tr>
            <tr><td class="meta-label">Confidence</td><td class="meta-value">${Math.round(waf.confidence * 100)}%</td></tr>
            <tr><td class="meta-label">Evasion Techniques Applied</td><td class="meta-value">${waf.evasionApplied.join(", ") || "None"}</td></tr>
          </table>
        ` : ""}
      </div>
    </div>`;
}
function renderCredentialResults(creds) {
  return `
    <div class="section">
      <h2 class="section-title">CREDENTIAL TESTING RESULTS</h2>
      <div class="summary-grid">
        <div class="summary-card">
          <div class="summary-label">Total Tested</div>
          <div class="summary-value">${creds.totalTested}</div>
        </div>
        <div class="summary-card" style="border-left: 4px solid ${creds.successfulLogins > 0 ? THEME.danger : THEME.success};">
          <div class="summary-label">Successful Logins</div>
          <div class="summary-value" style="color: ${creds.successfulLogins > 0 ? THEME.danger : THEME.success};">${creds.successfulLogins}</div>
        </div>
        <div class="summary-card">
          <div class="summary-label">Failed Attempts</div>
          <div class="summary-value">${creds.failedAttempts}</div>
        </div>
      </div>
      ${creds.confirmedCredentials.length > 0 ? `
        <h3 class="subsection-title" style="color: ${THEME.danger};">\u26A0 CONFIRMED DEFAULT CREDENTIALS</h3>
        <table class="data-table">
          <thead>
            <tr>
              <th>Host</th>
              <th>Port</th>
              <th>Protocol</th>
              <th>Username</th>
              <th>Access Level</th>
              <th>Product</th>
            </tr>
          </thead>
          <tbody>
            ${creds.confirmedCredentials.map((c) => `
              <tr>
                <td class="mono">${escapeHtml(c.host)}</td>
                <td>${c.port}</td>
                <td>${escapeHtml(c.protocol)}</td>
                <td class="mono" style="color: ${THEME.danger};">${escapeHtml(c.username)}</td>
                <td>${escapeHtml(c.accessLevel)}</td>
                <td>${escapeHtml(c.vendor)} ${escapeHtml(c.product)}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      ` : `<p style="color: ${THEME.success};">No default credentials confirmed.</p>`}
    </div>`;
}
function renderFindingsDetail(findings) {
  if (findings.length === 0) {
    return `<div class="section"><h2 class="section-title">FINDINGS DETAIL</h2><p>No findings recorded.</p></div>`;
  }
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sorted = [...findings].sort(
    (a, b) => (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5)
  );
  return `
    <div class="section">
      <h2 class="section-title">FINDINGS DETAIL</h2>
      ${sorted.map((f, i) => {
    const sev = SEVERITY_COLORS[f.severity] || SEVERITY_COLORS.info;
    return `
          <div class="finding-card" style="border-left: 4px solid ${sev.border};">
            <div class="finding-header">
              <span class="finding-number">#${i + 1}</span>
              <span class="finding-severity" style="background: ${sev.bg}; color: ${sev.text};">${f.severity.toUpperCase()}</span>
              <span class="finding-name">${escapeHtml(f.alertName)}</span>
              ${f.exploitAvailable ? `<span class="exploit-badge">EXPLOIT AVAILABLE</span>` : ""}
              ${f.aiTriageVerdict ? `<span class="triage-badge ${f.aiTriageVerdict === "false_positive" ? "fp" : "tp"}">${f.aiTriageVerdict === "false_positive" ? "FP" : "TP"}</span>` : ""}
            </div>
            <div class="finding-body">
              <table class="finding-meta">
                <tr><td>URL</td><td class="mono">${escapeHtml(f.url || "N/A")}</td></tr>
                ${f.method ? `<tr><td>Method</td><td>${f.method}</td></tr>` : ""}
                ${f.param ? `<tr><td>Parameter</td><td class="mono">${escapeHtml(f.param)}</td></tr>` : ""}
                <tr><td>Confidence</td><td>${Math.round(f.confidence * 100)}%</td></tr>
                ${f.cweId ? `<tr><td>CWE</td><td><a href="https://cwe.mitre.org/data/definitions/${f.cweId}.html" class="link">CWE-${f.cweId}</a></td></tr>` : ""}
                ${f.mitreAttackId ? `<tr><td>MITRE ATT&CK</td><td>${f.mitreAttackId} \u2014 ${escapeHtml(f.mitreAttackName || "")}<br><span class="tactic-label">${escapeHtml(f.mitreTactic || "")}</span></td></tr>` : ""}
                ${f.exploitModulePath ? `<tr><td>Exploit Module</td><td class="mono" style="color: ${THEME.danger};">${escapeHtml(f.exploitModulePath)}</td></tr>` : ""}
              </table>
              ${f.description ? `<div class="finding-section"><strong>Description</strong><p>${escapeHtml(f.description)}</p></div>` : ""}
              ${f.attack ? `<div class="finding-section"><strong>Attack</strong><pre class="code-block">${escapeHtml(f.attack)}</pre></div>` : ""}
              ${f.evidence ? `<div class="finding-section"><strong>Evidence</strong><pre class="code-block">${escapeHtml(f.evidence)}</pre></div>` : ""}
              ${f.solution ? `<div class="finding-section"><strong>Remediation</strong><p>${escapeHtml(f.solution)}</p></div>` : ""}
              ${f.reference ? `<div class="finding-section"><strong>References</strong><p class="mono" style="font-size: 11px;">${escapeHtml(f.reference)}</p></div>` : ""}
            </div>
          </div>`;
  }).join("")}
    </div>`;
}
function renderRemediationPriorities(findings) {
  const grouped = /* @__PURE__ */ new Map();
  for (const f of findings) {
    const key = f.alertName;
    if (!grouped.has(key)) grouped.set(key, { count: 0, exploitable: 0, names: [] });
    const g = grouped.get(key);
    g.count++;
    if (f.exploitAvailable) g.exploitable++;
  }
  const priorities = Array.from(grouped.entries()).map(([name, data]) => ({ name, ...data })).sort((a, b) => b.exploitable - a.exploitable || b.count - a.count).slice(0, 15);
  return `
    <div class="section">
      <h2 class="section-title">REMEDIATION PRIORITIES</h2>
      <p style="color: ${THEME.fgMuted}; margin-bottom: 16px;">
        Findings ranked by exploitability and occurrence count. Address exploitable findings first.
      </p>
      <table class="data-table">
        <thead>
          <tr>
            <th>Priority</th>
            <th>Finding</th>
            <th>Occurrences</th>
            <th>Exploitable</th>
          </tr>
        </thead>
        <tbody>
          ${priorities.map((p, i) => `
            <tr>
              <td><span class="priority-badge">${i < 3 ? "P1" : i < 7 ? "P2" : "P3"}</span></td>
              <td>${escapeHtml(p.name)}</td>
              <td>${p.count}</td>
              <td>${p.exploitable > 0 ? `<span style="color: ${THEME.danger};">Yes (${p.exploitable})</span>` : "No"}</td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>`;
}
function wrapInHtmlDocument(data, bodyContent) {
  const dateStr = data.generatedAt.toLocaleDateString("en-US", {
    year: "numeric",
    month: "long",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit"
  });
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${escapeHtml(data.reportTitle)}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

  * { margin: 0; padding: 0; box-sizing: border-box; }

  body {
    font-family: ${THEME.fontPrimary};
    background: ${THEME.bg};
    color: ${THEME.fg};
    line-height: 1.6;
    -webkit-font-smoothing: antialiased;
  }

  .page {
    max-width: 1000px;
    margin: 0 auto;
    padding: 40px 32px;
  }

  /* \u2500\u2500 Header \u2500\u2500 */
  .report-header {
    border-bottom: 2px solid ${THEME.accent};
    padding-bottom: 24px;
    margin-bottom: 40px;
  }

  .header-top {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 16px;
  }

  .brand {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .brand-logo {
    width: 48px;
    height: 48px;
    border-radius: 8px;
    overflow: hidden;
  }
  .brand-logo img {
    width: 100%;
    height: 100%;
    object-fit: contain;
  }

  .brand-name {
    font-size: 18px;
    font-weight: 700;
    color: ${THEME.fg};
    letter-spacing: 0.5px;
  }

  .brand-sub {
    font-size: 10px;
    color: ${THEME.fgMuted};
    text-transform: uppercase;
    letter-spacing: 2px;
    font-weight: 500;
  }

  .classification {
    background: ${THEME.bgCard};
    border: 1px solid ${THEME.border};
    color: ${THEME.fgMuted};
    padding: 4px 12px;
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 2px;
    text-transform: uppercase;
    font-family: ${THEME.fontMono};
  }

  .report-title {
    font-size: 24px;
    font-weight: 800;
    color: ${THEME.fg};
    margin-bottom: 4px;
    letter-spacing: -0.5px;
  }

  .report-subtitle {
    font-size: 14px;
    color: ${THEME.accent};
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 1px;
  }

  .report-date {
    font-size: 12px;
    color: ${THEME.fgMuted};
    margin-top: 8px;
    font-family: ${THEME.fontMono};
  }

  ${data.engagement ? `
  .engagement-info {
    background: ${THEME.bgCard};
    border: 1px solid ${THEME.border};
    padding: 16px;
    margin-top: 16px;
  }
  ` : ""}

  /* \u2500\u2500 Sections \u2500\u2500 */
  .section {
    margin-bottom: 40px;
    page-break-inside: avoid;
  }

  .section-title {
    font-size: 14px;
    font-weight: 700;
    color: ${THEME.accent};
    text-transform: uppercase;
    letter-spacing: 3px;
    margin-bottom: 20px;
    padding-bottom: 8px;
    border-bottom: 1px solid ${THEME.border};
    font-family: ${THEME.fontMono};
  }

  .subsection-title {
    font-size: 13px;
    font-weight: 600;
    margin: 16px 0 12px;
    text-transform: uppercase;
    letter-spacing: 1px;
  }

  /* \u2500\u2500 Summary Grid \u2500\u2500 */
  .summary-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 12px;
    margin-bottom: 20px;
  }

  .summary-card {
    background: ${THEME.bgCard};
    border: 1px solid ${THEME.border};
    padding: 16px;
  }

  .summary-label {
    font-size: 10px;
    color: ${THEME.fgMuted};
    text-transform: uppercase;
    letter-spacing: 1.5px;
    font-weight: 600;
    margin-bottom: 6px;
  }

  .summary-value {
    font-size: 18px;
    font-weight: 700;
    color: ${THEME.fg};
    word-break: break-all;
  }

  .mono { font-family: ${THEME.fontMono}; font-size: 12px; }

  /* \u2500\u2500 Alert Bar \u2500\u2500 */
  .alert-summary { margin-bottom: 20px; }

  .alert-bar {
    display: flex;
    height: 8px;
    border-radius: 4px;
    overflow: hidden;
    margin-bottom: 8px;
    background: ${THEME.border};
  }

  .alert-segment { min-width: 4px; }

  .alert-counts {
    display: flex;
    gap: 16px;
    flex-wrap: wrap;
    font-size: 12px;
    font-weight: 500;
  }

  /* \u2500\u2500 Tech Tags \u2500\u2500 */
  .tech-tags { display: flex; flex-wrap: wrap; gap: 6px; }

  .tech-tag {
    background: ${THEME.accentDim};
    color: ${THEME.accent};
    padding: 3px 10px;
    font-size: 11px;
    font-weight: 600;
    font-family: ${THEME.fontMono};
    border: 1px solid rgba(0, 229, 204, 0.3);
  }

  /* \u2500\u2500 Meta Table \u2500\u2500 */
  .meta-table { width: 100%; margin-top: 12px; }

  .meta-table td {
    padding: 6px 12px;
    border-bottom: 1px solid ${THEME.border};
    font-size: 13px;
  }

  .meta-label {
    color: ${THEME.fgMuted};
    font-weight: 600;
    width: 160px;
    text-transform: uppercase;
    font-size: 10px !important;
    letter-spacing: 1px;
  }

  .meta-value { color: ${THEME.fg}; }

  /* \u2500\u2500 Data Table \u2500\u2500 */
  .data-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }

  .data-table th {
    background: ${THEME.bgCard};
    color: ${THEME.fgMuted};
    padding: 10px 12px;
    text-align: left;
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 1px;
    font-weight: 600;
    border-bottom: 2px solid ${THEME.border};
  }

  .data-table td {
    padding: 10px 12px;
    border-bottom: 1px solid ${THEME.border};
    color: ${THEME.fg};
  }

  .data-table tr:hover td { background: rgba(255, 255, 255, 0.02); }

  /* \u2500\u2500 Risk Score \u2500\u2500 */
  .risk-grid {
    display: grid;
    grid-template-columns: 200px 1fr;
    gap: 24px;
    align-items: center;
  }

  .risk-score-card { text-align: center; }

  .risk-score-circle {
    width: 120px;
    height: 120px;
    border-radius: 50%;
    border: 4px solid var(--color, ${THEME.accent});
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    margin: 0 auto 8px;
    background: ${THEME.bgCard};
  }

  .risk-score-number {
    font-size: 36px;
    font-weight: 800;
    color: var(--color, ${THEME.accent});
    line-height: 1;
  }

  .risk-score-label {
    font-size: 12px;
    color: ${THEME.fgMuted};
  }

  .risk-score-desc {
    font-size: 11px;
    color: ${THEME.fgMuted};
    text-transform: uppercase;
    letter-spacing: 1px;
  }

  .risk-metrics {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
  }

  .risk-metric {
    background: ${THEME.bgCard};
    border: 1px solid ${THEME.border};
    padding: 16px;
    text-align: center;
  }

  .risk-metric-value {
    display: block;
    font-size: 28px;
    font-weight: 800;
    line-height: 1.2;
  }

  .risk-metric-label {
    display: block;
    font-size: 10px;
    color: ${THEME.fgMuted};
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-top: 4px;
  }

  /* \u2500\u2500 OWASP \u2500\u2500 */
  .owasp-summary {
    display: flex;
    gap: 24px;
    margin-bottom: 16px;
    font-size: 14px;
    font-weight: 600;
  }

  .findings-list {
    font-size: 11px;
    color: ${THEME.fgMuted};
    max-width: 300px;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  /* \u2500\u2500 MITRE \u2500\u2500 */
  .mitre-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 12px;
  }

  .mitre-tactic {
    background: ${THEME.bgCard};
    border: 1px solid ${THEME.border};
    padding: 12px;
  }

  .mitre-tactic-header {
    font-size: 11px;
    font-weight: 700;
    color: ${THEME.accent};
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 8px;
    padding-bottom: 6px;
    border-bottom: 1px solid ${THEME.border};
  }

  .mitre-technique {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 4px 0;
    font-size: 12px;
  }

  .mitre-id {
    font-family: ${THEME.fontMono};
    font-size: 11px;
    color: ${THEME.accent};
    font-weight: 600;
    min-width: 60px;
  }

  .mitre-name { color: ${THEME.fg}; flex: 1; }

  .mitre-count {
    background: ${THEME.accentDim};
    color: ${THEME.accent};
    padding: 1px 6px;
    font-size: 10px;
    font-weight: 600;
    font-family: ${THEME.fontMono};
  }

  /* \u2500\u2500 WAF Card \u2500\u2500 */
  .waf-card {
    background: ${THEME.bgCard};
    border: 1px solid ${THEME.border};
    padding: 16px;
  }

  .waf-status {
    font-size: 16px;
    font-weight: 700;
    margin-bottom: 12px;
  }

  /* \u2500\u2500 Findings \u2500\u2500 */
  .finding-card {
    background: ${THEME.bgCard};
    border: 1px solid ${THEME.border};
    margin-bottom: 16px;
    page-break-inside: avoid;
  }

  .finding-header {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 12px 16px;
    border-bottom: 1px solid ${THEME.border};
    flex-wrap: wrap;
  }

  .finding-number {
    font-family: ${THEME.fontMono};
    font-size: 12px;
    color: ${THEME.fgMuted};
    font-weight: 600;
  }

  .finding-severity {
    padding: 2px 8px;
    font-size: 10px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1px;
    font-family: ${THEME.fontMono};
  }

  .finding-name {
    font-weight: 600;
    font-size: 14px;
    flex: 1;
  }

  .exploit-badge {
    background: ${THEME.dangerDim};
    color: ${THEME.danger};
    padding: 2px 8px;
    font-size: 9px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 1px;
    font-family: ${THEME.fontMono};
    border: 1px solid rgba(255, 68, 68, 0.3);
  }

  .triage-badge {
    padding: 2px 8px;
    font-size: 9px;
    font-weight: 700;
    font-family: ${THEME.fontMono};
  }

  .triage-badge.tp { background: ${THEME.dangerDim}; color: ${THEME.danger}; }
  .triage-badge.fp { background: rgba(139, 155, 180, 0.15); color: ${THEME.fgMuted}; text-decoration: line-through; }

  .finding-body { padding: 16px; }

  .finding-meta { width: 100%; margin-bottom: 12px; }

  .finding-meta td {
    padding: 4px 8px;
    font-size: 12px;
    border-bottom: 1px solid rgba(30, 42, 58, 0.5);
  }

  .finding-meta td:first-child {
    color: ${THEME.fgMuted};
    font-weight: 600;
    width: 120px;
    text-transform: uppercase;
    font-size: 10px;
    letter-spacing: 1px;
  }

  .finding-section {
    margin-top: 12px;
  }

  .finding-section strong {
    display: block;
    font-size: 11px;
    color: ${THEME.accent};
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 4px;
  }

  .finding-section p {
    font-size: 13px;
    color: ${THEME.fgMuted};
    line-height: 1.5;
  }

  .code-block {
    background: ${THEME.bg};
    border: 1px solid ${THEME.border};
    padding: 10px 12px;
    font-family: ${THEME.fontMono};
    font-size: 11px;
    color: ${THEME.accent};
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-all;
  }

  .link {
    color: ${THEME.accent};
    text-decoration: none;
  }

  .link:hover { text-decoration: underline; }

  .tactic-label {
    font-size: 10px;
    color: ${THEME.fgMuted};
    font-style: italic;
  }

  /* \u2500\u2500 Priority Badge \u2500\u2500 */
  .priority-badge {
    font-family: ${THEME.fontMono};
    font-size: 10px;
    font-weight: 700;
    padding: 2px 6px;
    background: ${THEME.accentDim};
    color: ${THEME.accent};
  }

  /* \u2500\u2500 Footer \u2500\u2500 */
  .report-footer {
    margin-top: 48px;
    padding-top: 16px;
    border-top: 1px solid ${THEME.border};
    text-align: center;
    font-size: 10px;
    color: ${THEME.fgMuted};
    font-family: ${THEME.fontMono};
    letter-spacing: 1px;
  }

  /* \u2500\u2500 Print Styles \u2500\u2500 */
  @media print {
    body { background: #fff; color: #000; }
    .page { padding: 20px; }
    .report-header { border-bottom-color: #000; }
    .section-title { color: #000; border-bottom-color: #ccc; }
    .summary-card, .finding-card, .mitre-tactic, .waf-card {
      background: #f9f9f9;
      border-color: #ddd;
    }
    .data-table th { background: #eee; color: #333; }
    .code-block { background: #f5f5f5; color: #333; border-color: #ddd; }
    .tech-tag { background: #e0f7f4; color: #00897b; border-color: #00897b; }
  }

  @page {
    margin: 1cm;
    size: A4;
  }
</style>
</head>
<body>
<div class="page">
  <div class="report-header">
    <div class="header-top">
      <div class="brand">
        <div class="brand-logo"><img src="https://d2xsxph8kpxj0f.cloudfront.net/310419663028432609/VmWWcXQYZJYuALRdNNvsC2/ace_of_cloud_logo_8934407a.jpeg" alt="Ace of Cloud" /></div>
        <div>
          <div class="brand-name">ACE OF CLOUD \u2014 AC3</div>
          <div class="brand-sub">Web Application Security Assessment</div>
        </div>
      </div>
      <div class="classification">${data.classification}</div>
    </div>
    <div class="report-title">${escapeHtml(data.reportTitle)}</div>
    <div class="report-subtitle">${data.reportType.toUpperCase()} REPORT</div>
    <div class="report-date">Generated: ${dateStr}</div>
    ${data.engagement ? `
      <div class="engagement-info">
        <table class="meta-table">
          <tr><td class="meta-label">Client</td><td class="meta-value">${escapeHtml(data.engagement.clientName)}</td></tr>
          <tr><td class="meta-label">Engagement</td><td class="meta-value">${escapeHtml(data.engagement.engagementName)}</td></tr>
          <tr><td class="meta-label">Period</td><td class="meta-value">${data.engagement.startDate} \u2014 ${data.engagement.endDate}</td></tr>
          <tr><td class="meta-label">Scope</td><td class="meta-value">${escapeHtml(data.engagement.scopeDescription)}</td></tr>
          <tr><td class="meta-label">Tester</td><td class="meta-value">${escapeHtml(data.engagement.testerName)} \u2014 ${escapeHtml(data.engagement.testerOrg)}</td></tr>
        </table>
      </div>
    ` : ""}
  </div>

  ${bodyContent}

  <div class="report-footer">
    ACE OF CLOUD LLC \u2014 AC3 PLATFORM &nbsp;|&nbsp; aceofcloud.com &nbsp;|&nbsp; ${dateStr}
    <br>
    This report is ${data.classification}. Distribution is restricted to authorized personnel only.
  </div>
</div>
</body>
</html>`;
}
function escapeHtml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}
async function generateReportFromZapApi(scanId, reportType = "full", engagement) {
  const { getDb } = await import("./db-OF4HQS7N.js");
  const { webAppScans, webAppFindings } = await import("./schema-R6EY37IN.js");
  const { eq } = await import("drizzle-orm");
  const db = await getDb();
  if (!db) throw new Error("Database unavailable");
  const [scan] = await db.select().from(webAppScans).where(eq(webAppScans.id, scanId));
  if (!scan) throw new Error(`Scan ${scanId} not found`);
  const findings = await db.select().from(webAppFindings).where(eq(webAppFindings.scanId, scanId));
  const alertCounts = scan.alertCounts ? JSON.parse(scan.alertCounts) : { high: 0, medium: 0, low: 0, info: 0 };
  const techStack = scan.detectedTechStack ? JSON.parse(scan.detectedTechStack) : [];
  const startMs = scan.startedAt ? new Date(scan.startedAt).getTime() : 0;
  const endMs = scan.completedAt ? new Date(scan.completedAt).getTime() : Date.now();
  const durationMin = Math.round((endMs - startMs) / 6e4);
  const duration = durationMin > 60 ? `${Math.floor(durationMin / 60)}h ${durationMin % 60}m` : `${durationMin}m`;
  const mitreMap = /* @__PURE__ */ new Map();
  for (const f of findings) {
    if (f.mitreAttackId) {
      const existing = mitreMap.get(f.mitreAttackId);
      if (existing) existing.count++;
      else mitreMap.set(f.mitreAttackId, {
        techniqueName: f.mitreAttackName || "",
        tactic: f.mitreTactic || "",
        count: 1
      });
    }
  }
  const reportData = {
    reportTitle: `Web Application Scan Report \u2014 ${scan.scanName || scan.targetUrl}`,
    reportType,
    generatedAt: /* @__PURE__ */ new Date(),
    classification: "CONFIDENTIAL",
    engagement,
    scan: {
      targetUrl: scan.targetUrl,
      scanName: scan.scanName || scan.targetUrl,
      scanMode: scan.scanMode || "passive",
      scanType: scan.scanType || "full",
      startedAt: scan.startedAt ? new Date(scan.startedAt).toLocaleString() : "N/A",
      completedAt: scan.completedAt ? new Date(scan.completedAt).toLocaleString() : "In Progress",
      duration,
      urlsDiscovered: scan.urlsDiscovered || 0,
      techStack,
      attackChainId: scan.attackChainId || void 0
    },
    alertCounts: {
      critical: alertCounts.critical || 0,
      high: alertCounts.high || 0,
      medium: alertCounts.medium || 0,
      low: alertCounts.low || 0,
      info: alertCounts.info || 0,
      total: findings.length
    },
    findings: findings.map((f, i) => ({
      id: i + 1,
      alertName: f.alertName || "Unknown",
      severity: f.severity || "info",
      confidence: f.confidence || 0,
      description: f.description || "",
      solution: f.solution || "",
      reference: f.reference || "",
      url: f.url || "",
      method: f.method || "",
      param: f.param || "",
      attack: f.attack || "",
      evidence: f.evidence || "",
      cweId: f.cweId || null,
      wascId: f.wascId || null,
      mitreAttackId: f.mitreAttackId || null,
      mitreAttackName: f.mitreAttackName || null,
      mitreTactic: f.mitreTactic || null,
      exploitAvailable: f.exploitAvailable || false,
      exploitModulePath: f.exploitModulePath || null,
      aiTriageVerdict: f.aiTriageVerdict || null,
      falsePositiveScore: f.falsePositiveScore || null
    })),
    mitreMapping: Array.from(mitreMap.entries()).map(([id, data]) => ({
      techniqueId: id,
      ...data,
      findingCount: data.count
    }))
  };
  return generateThemedReport(reportData);
}
export {
  generateReportFromZapApi,
  generateThemedReport
};
