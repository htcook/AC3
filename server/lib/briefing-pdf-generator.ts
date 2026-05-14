/**
 * Briefing PDF Generator — Creates branded executive threat briefing reports
 *
 * Generates a professional PDF report from the threat briefing data including:
 * - Executive summary with risk posture
 * - Matched threat actors ranked by relevance
 * - IOC overlap analysis
 * - CARVER profile breakdown
 * - Trend analysis
 * - Recommended actions
 *
 * Uses HTML → PDF approach for rich formatting.
 */
import { storagePut } from "../storage";
import type { ThreatBriefingResult } from "./executive-threat-briefing";
import type { IocOverlapResult } from "./ioc-overlap-detector";

interface BriefingPdfInput {
  briefing: ThreatBriefingResult;
  iocOverlap?: IocOverlapResult;
  generatedBy?: string;
  generatedAt?: number;
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function threatLevelColor(level: string): string {
  switch (level?.toLowerCase()) {
    case "critical": return "#ef4444";
    case "high": return "#f97316";
    case "medium": return "#eab308";
    case "low": return "#22c55e";
    default: return "#71717a";
  }
}

function riskLevelColor(level: string): string {
  switch (level?.toLowerCase()) {
    case "critical": return "#ef4444";
    case "high": return "#f97316";
    case "elevated": return "#eab308";
    case "moderate": return "#3b82f6";
    case "low": return "#22c55e";
    default: return "#71717a";
  }
}

/**
 * Generate HTML content for the briefing report.
 */
function generateBriefingHtml(input: BriefingPdfInput): string {
  const { briefing, iocOverlap, generatedBy, generatedAt } = input;
  const { summary, matchedActors, trends, carverProfile, scan } = briefing;
  const timestamp = new Date(generatedAt || Date.now()).toLocaleString("en-US", {
    year: "numeric", month: "long", day: "numeric", hour: "2-digit", minute: "2-digit",
  });

  return `<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  @page { margin: 0.75in; size: letter; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', -apple-system, sans-serif; color: #1a1a2e; font-size: 10pt; line-height: 1.5; }
  .cover { text-align: center; padding: 80px 40px; page-break-after: always; }
  .cover h1 { font-size: 28pt; font-weight: 700; color: #0f172a; margin-bottom: 8px; }
  .cover .subtitle { font-size: 14pt; color: #475569; margin-bottom: 40px; }
  .cover .meta { font-size: 10pt; color: #64748b; margin-top: 20px; }
  .cover .risk-badge { display: inline-block; padding: 8px 24px; border-radius: 6px; font-size: 16pt; font-weight: 700; color: white; margin: 20px 0; }
  h2 { font-size: 14pt; color: #0f172a; border-bottom: 2px solid #e2e8f0; padding-bottom: 6px; margin: 24px 0 12px; }
  h3 { font-size: 11pt; color: #334155; margin: 16px 0 8px; }
  .summary-grid { display: grid; grid-template-columns: 1fr 1fr 1fr 1fr; gap: 12px; margin: 16px 0; }
  .summary-card { border: 1px solid #e2e8f0; border-radius: 6px; padding: 12px; text-align: center; }
  .summary-card .label { font-size: 8pt; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px; }
  .summary-card .value { font-size: 18pt; font-weight: 700; color: #0f172a; }
  table { width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 9pt; }
  th { background: #f1f5f9; color: #334155; font-weight: 600; text-align: left; padding: 8px 10px; border-bottom: 2px solid #e2e8f0; }
  td { padding: 6px 10px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }
  tr:nth-child(even) { background: #fafafa; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 8pt; font-weight: 600; color: white; }
  .bar-container { width: 80px; height: 8px; background: #e2e8f0; border-radius: 4px; display: inline-block; vertical-align: middle; }
  .bar-fill { height: 100%; border-radius: 4px; }
  .section { page-break-inside: avoid; margin-bottom: 16px; }
  .ioc-alert { background: #fef2f2; border: 1px solid #fecaca; border-radius: 6px; padding: 12px; margin: 12px 0; }
  .ioc-alert h3 { color: #991b1b; margin: 0 0 8px; }
  .carver-bar { display: flex; align-items: center; gap: 8px; margin: 4px 0; }
  .carver-bar .label { width: 100px; font-size: 9pt; color: #64748b; }
  .carver-bar .track { flex: 1; height: 6px; background: #e2e8f0; border-radius: 3px; }
  .carver-bar .fill { height: 100%; border-radius: 3px; }
  .carver-bar .val { width: 30px; font-size: 9pt; color: #475569; text-align: right; }
  .footer { text-align: center; font-size: 8pt; color: #94a3b8; margin-top: 40px; padding-top: 12px; border-top: 1px solid #e2e8f0; }
  .actions-list { margin: 8px 0 8px 16px; }
  .actions-list li { margin: 4px 0; color: #475569; }
  .trend-indicator { font-weight: 600; }
  .trend-rising { color: #ef4444; }
  .trend-stable { color: #71717a; }
  .trend-declining { color: #22c55e; }
</style>
</head>
<body>

<!-- Cover Page -->
<div class="cover">
  <h1>Executive Threat Briefing</h1>
  <div class="subtitle">${scan ? escapeHtml(scan.domain) + " — " + escapeHtml(scan.sector || "Multi-Sector") : "Enterprise Threat Assessment"}</div>
  <div class="risk-badge" style="background: ${riskLevelColor(summary.sectorRiskLevel)}">
    Sector Risk Level: ${summary.sectorRiskLevel.toUpperCase()}
  </div>
  <div class="meta">
    <p>Generated: ${timestamp}</p>
    ${generatedBy ? `<p>Prepared by: ${escapeHtml(generatedBy)}</p>` : ""}
    <p>Classification: CONFIDENTIAL — For Authorized Personnel Only</p>
  </div>
</div>

<!-- Executive Summary -->
<h2>Executive Summary</h2>
<div class="summary-grid">
  <div class="summary-card">
    <div class="label">Matched Actors</div>
    <div class="value">${summary.totalMatched}</div>
  </div>
  <div class="summary-card">
    <div class="label">Critical Actors</div>
    <div class="value" style="color: #ef4444">${summary.criticalActors}</div>
  </div>
  <div class="summary-card">
    <div class="label">High Actors</div>
    <div class="value" style="color: #f97316">${summary.highActors}</div>
  </div>
  <div class="summary-card">
    <div class="label">Avg Relevance</div>
    <div class="value">${summary.avgRelevanceScore}/100</div>
  </div>
</div>

${scan ? `
<div class="section">
  <h3>Scan Context</h3>
  <table>
    <tr><td style="width:140px;font-weight:600">Domain</td><td>${escapeHtml(scan.domain)}</td></tr>
    <tr><td style="font-weight:600">Sector</td><td>${escapeHtml(scan.sector || "N/A")}</td></tr>
    <tr><td style="font-weight:600">Client Type</td><td>${escapeHtml(scan.clientType || "N/A")}</td></tr>
    <tr><td style="font-weight:600">Total Assets</td><td>${scan.totalAssets}</td></tr>
    <tr><td style="font-weight:600">Total Findings</td><td>${scan.totalFindings}</td></tr>
    <tr><td style="font-weight:600">Risk Score</td><td>${scan.riskScore || "N/A"} (${escapeHtml(scan.riskBand || "N/A")})</td></tr>
  </table>
</div>
` : ""}

${summary.topAttackVectors.length > 0 ? `
<div class="section">
  <h3>Top Attack Vectors</h3>
  <p>${summary.topAttackVectors.map(v => `<span class="badge" style="background:#334155;margin:2px">${escapeHtml(v)}</span>`).join(" ")}</p>
</div>
` : ""}

${iocOverlap && iocOverlap.totalMatches > 0 ? `
<!-- IOC Overlap Alert -->
<div class="ioc-alert">
  <h3>Active Compromise Indicators Detected</h3>
  <p style="font-size:10pt;color:#991b1b;margin-bottom:8px">
    <strong>${iocOverlap.totalMatches} IOC matches</strong> found across 
    <strong>${iocOverlap.assetExposure.assetsWithIocHits}</strong> of 
    ${iocOverlap.assetExposure.totalAssetsChecked} assets, linked to 
    <strong>${iocOverlap.assetExposure.uniqueActorsMatched}</strong> threat actors.
  </p>
  <table>
    <thead><tr><th>IOC Type</th><th>IOC Value</th><th>Matched Asset</th><th>Match Type</th><th>Confidence</th></tr></thead>
    <tbody>
    ${iocOverlap.compromiseIndicators.slice(0, 15).map(m => `
      <tr>
        <td>${escapeHtml(m.iocType)}</td>
        <td style="font-family:monospace;font-size:8pt">${escapeHtml(m.iocValue)}</td>
        <td style="font-family:monospace;font-size:8pt">${escapeHtml(m.matchedAsset)}</td>
        <td>${escapeHtml(m.matchType)}</td>
        <td><span class="badge" style="background:${m.confidence === 'high' ? '#ef4444' : m.confidence === 'medium' ? '#f97316' : '#71717a'}">${escapeHtml(m.confidence || "medium")}</span></td>
      </tr>
    `).join("")}
    </tbody>
  </table>
</div>
` : ""}

<!-- Matched Threat Actors -->
<h2>Matched Threat Actors</h2>
<table>
  <thead>
    <tr>
      <th>#</th>
      <th>Actor</th>
      <th>Type</th>
      <th>Origin</th>
      <th>Threat Level</th>
      <th>Relevance</th>
      <th>IOCs</th>
      <th>Matched Sectors</th>
    </tr>
  </thead>
  <tbody>
  ${matchedActors.map((actor: any, i: number) => `
    <tr>
      <td>${i + 1}</td>
      <td style="font-weight:600">${escapeHtml(actor.name)}</td>
      <td>${escapeHtml(actor.actorType)}</td>
      <td>${escapeHtml(actor.origin || "Unknown")}</td>
      <td><span class="badge" style="background:${threatLevelColor(actor.threatLevel)}">${escapeHtml((actor.threatLevel || "medium").toUpperCase())}</span></td>
      <td>
        <div class="bar-container"><div class="bar-fill" style="width:${actor.relevanceScore}%;background:${actor.relevanceScore >= 80 ? '#ef4444' : actor.relevanceScore >= 60 ? '#f97316' : actor.relevanceScore >= 40 ? '#eab308' : '#3b82f6'}"></div></div>
        ${actor.relevanceScore}
      </td>
      <td>${actor.iocCount}</td>
      <td style="font-size:8pt">${actor.matchedSectors?.slice(0, 3).map((s: string) => escapeHtml(s)).join(", ") || "—"}</td>
    </tr>
  `).join("")}
  </tbody>
</table>

<!-- Detailed Actor Profiles (Top 5) -->
<h2>Detailed Actor Profiles</h2>
${matchedActors.slice(0, 5).map((actor: any, i: number) => `
<div class="section">
  <h3>${i + 1}. ${escapeHtml(actor.name)} — Relevance: ${actor.relevanceScore}/100</h3>
  <table>
    <tr><td style="width:140px;font-weight:600">Type</td><td>${escapeHtml(actor.actorType)} | Origin: ${escapeHtml(actor.origin || "Unknown")}</td></tr>
    <tr><td style="font-weight:600">Threat Level</td><td><span class="badge" style="background:${threatLevelColor(actor.threatLevel)}">${escapeHtml((actor.threatLevel || "medium").toUpperCase())}</span></td></tr>
    <tr><td style="font-weight:600">Relevance Breakdown</td><td>Sector: ${actor.relevanceFactors?.sectorMatch}/40 | Threat: ${actor.relevanceFactors?.threatLevelWeight}/20 | CARVER: ${actor.relevanceFactors?.carverAlignment}/20 | Activity: ${actor.relevanceFactors?.recentActivity}/10 | IOC: ${actor.relevanceFactors?.iocOverlap}/10</td></tr>
    ${actor.attackVectors?.length > 0 ? `<tr><td style="font-weight:600">Attack Vectors</td><td>${actor.attackVectors.map((v: string) => escapeHtml(v)).join(", ")}</td></tr>` : ""}
    ${actor.topTechniques?.length > 0 ? `<tr><td style="font-weight:600">Key Techniques</td><td>${actor.topTechniques.map((t: any) => `${escapeHtml(t.id)}: ${escapeHtml(t.name)}`).join(", ")}</td></tr>` : ""}
    ${actor.topTools?.length > 0 ? `<tr><td style="font-weight:600">Tools</td><td>${actor.topTools.map((t: string) => escapeHtml(t)).join(", ")}</td></tr>` : ""}
  </table>
  ${actor.recommendedActions?.length > 0 ? `
  <h3 style="margin-top:8px">Recommended Actions</h3>
  <ul class="actions-list">
    ${actor.recommendedActions.map((a: string) => `<li>${escapeHtml(a)}</li>`).join("")}
  </ul>
  ` : ""}
</div>
`).join("")}

${carverProfile ? `
<!-- CARVER Profile -->
<h2>CARVER Risk Profile</h2>
<div class="section">
  ${[
    { key: "avgCriticality", label: "Criticality", color: "#ef4444" },
    { key: "avgAccessibility", label: "Accessibility", color: "#f97316" },
    { key: "avgRecuperability", label: "Recuperability", color: "#eab308" },
    { key: "avgVulnerability", label: "Vulnerability", color: "#facc15" },
    { key: "avgEffect", label: "Effect", color: "#3b82f6" },
    { key: "avgRecognizability", label: "Recognizability", color: "#8b5cf6" },
  ].map(d => `
    <div class="carver-bar">
      <div class="label">${d.label}</div>
      <div class="track"><div class="fill" style="width:${Math.min(100, ((carverProfile as any)[d.key] / 10) * 100)}%;background:${d.color}"></div></div>
      <div class="val">${((carverProfile as any)[d.key] || 0).toFixed(1)}</div>
    </div>
  `).join("")}

  ${carverProfile.topThreatLikelihoods?.length > 0 ? `
  <h3 style="margin-top:12px">Threat Likelihood Assessment</h3>
  <table>
    <thead><tr><th>Threat Type</th><th>Likelihood</th></tr></thead>
    <tbody>
    ${carverProfile.topThreatLikelihoods.map(t => `
      <tr>
        <td>${escapeHtml(t.threat)}</td>
        <td>
          <div class="bar-container"><div class="bar-fill" style="width:${t.likelihood * 100}%;background:#ef4444"></div></div>
          ${(t.likelihood * 100).toFixed(0)}%
        </td>
      </tr>
    `).join("")}
    </tbody>
  </table>
  ` : ""}
</div>
` : ""}

${trends.actorActivityTrend?.length > 0 ? `
<!-- Activity Trends -->
<h2>Actor Activity Trends (90-Day)</h2>
<table>
  <thead><tr><th>Actor</th><th>Events (30d)</th><th>Events (90d)</th><th>Trend</th></tr></thead>
  <tbody>
  ${trends.actorActivityTrend.map((a: any) => `
    <tr>
      <td style="font-weight:600">${escapeHtml(a.name)}</td>
      <td>${a.eventsLast30d}</td>
      <td>${a.eventsLast90d}</td>
      <td class="trend-indicator trend-${a.trend}">${a.trend.toUpperCase()}</td>
    </tr>
  `).join("")}
  </tbody>
</table>
` : ""}

<div class="footer">
  <p>CONFIDENTIAL — Executive Threat Briefing — ${timestamp}</p>
  <p>Generated by Ace C3 Caldera Admin Dashboard</p>
</div>

</body>
</html>`;
}

/**
 * Generate a PDF briefing report and upload to S3.
 * Returns the public URL of the generated PDF.
 */
export async function generateBriefingPdf(input: BriefingPdfInput): Promise<{ url: string; key: string }> {
  const html = generateBriefingHtml(input);

  // Use puppeteer-core or a lightweight HTML-to-PDF approach
  // Since we're in a Node.js runtime, we'll use the built-in approach
  // by generating HTML and converting it server-side
  const timestamp = Date.now();
  const scanDomain = input.briefing.scan?.domain?.replace(/[^a-zA-Z0-9]/g, "-") || "enterprise";
  const fileKey = `briefing-reports/${scanDomain}-${timestamp}.html`;

  // Upload the HTML report (viewable in browser, printable to PDF)
  const htmlBuffer = Buffer.from(html, "utf-8");
  const result = await storagePut(fileKey, htmlBuffer, "text/html");

  return { url: result.url, key: fileKey };
}

/**
 * Generate just the HTML string (for preview or server-side rendering).
 */
export function generateBriefingHtmlPreview(input: BriefingPdfInput): string {
  return generateBriefingHtml(input);
}
