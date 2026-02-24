/**
 * FedRAMP-Compliant Rules of Engagement PDF Generator
 * 
 * Generates a professional HTML document suitable for print-to-PDF that follows
 * NIST SP 800-115, FedRAMP, PTES, and OSSTMM formatting requirements.
 * 
 * Structure:
 *   1. Cover Page with classification markings
 *   2. Document Control (version, dates, distribution)
 *   3. Table of Contents
 *   4. Authorization & Purpose
 *   5. Scope (in-scope/out-of-scope assets)
 *   6. Testing Methodology
 *   7. Schedule & Logistics
 *   8. Communication Plan
 *   9. Data Handling & Evidence
 *  10. Legal & Compliance
 *  11. Personnel & Points of Contact
 *  12. Signature Blocks
 *  13. Appendices
 * 
 * Authored by Harrison Cook — AceofCloud
 */

export interface RoePdfData {
  document: any;
  personnel: any[];
  signatures: any[];
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function esc(str: string | null | undefined): string {
  if (!str) return "";
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function formatDate(d: any): string {
  if (!d) return "TBD";
  const date = new Date(d);
  return date.toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });
}

function formatTime(t: string | null | undefined): string {
  if (!t) return "TBD";
  return t;
}

function boolLabel(v: boolean | null | undefined): string {
  if (v === true) return "Yes";
  if (v === false) return "No";
  return "N/A";
}

const ROLE_LABELS: Record<string, string> = {
  system_owner: "System Owner",
  ciso: "Chief Information Security Officer (CISO)",
  cio: "Chief Information Officer (CIO)",
  isso: "Information System Security Officer (ISSO)",
  authorizing_official: "Authorizing Official (AO)",
  trusted_agent: "Trusted Agent",
  test_lead: "Test Lead",
  test_member: "Test Team Member",
  emergency_contact: "Emergency Contact",
  legal_counsel: "Legal Counsel",
  third_party_poc: "Third-Party Point of Contact",
  incident_response_lead: "Incident Response Lead",
  customer_poc: "Customer Point of Contact",
  project_manager: "Project Manager",
};

const SIGNER_ROLE_LABELS: Record<string, string> = {
  customer_executive: "Customer Executive",
  customer_technical: "Customer Technical Lead",
  testing_lead: "Testing Lead",
  authorizing_official: "Authorizing Official",
  legal_counsel: "Legal Counsel",
};

// ─── Main Generator ──────────────────────────────────────────────────────────

export function generateRoePdfHtml(data: RoePdfData): string {
  const doc = data.document;
  const personnel = data.personnel || [];
  const signatures = data.signatures || [];

  const testingTypes = (doc.testingTypes || []) as any[];
  const attackVectors = (doc.attackVectors || []) as any[];
  const reportDeliverables = (doc.reportDeliverables || []) as any[];
  const inScopeAssets = (doc.inScopeAssets || []) as any[];
  const outOfScopeAssets = (doc.outOfScopeAssets || []) as any[];
  const inScopeIpRanges = (doc.inScopeIpRanges || []) as any[];
  const outOfScopeIpRanges = (doc.outOfScopeIpRanges || []) as any[];
  const inScopeDomains = (doc.inScopeDomains || []) as any[];
  const outOfScopeDomains = (doc.outOfScopeDomains || []) as any[];
  const inScopeApplications = (doc.inScopeApplications || []) as any[];
  const cloudEnvironments = (doc.cloudEnvironments || []) as any[];
  const testingDays = (doc.testingDays || []) as string[];
  const complianceFrameworks = (doc.complianceFrameworks || []) as string[];
  const thirdPartyAgreements = (doc.thirdPartyAgreements || []) as any[];
  const enabledTypes = testingTypes.filter((t: any) => t.enabled);
  const enabledVectors = attackVectors.filter((v: any) => v.enabled);
  const requiredDeliverables = reportDeliverables.filter((d: any) => d.required);
  const optionalDeliverables = reportDeliverables.filter((d: any) => !d.required);

  const fedrampBadge = doc.fedrampCompliant
    ? `<span class="fedramp-badge">FedRAMP ${esc(doc.fedrampImpactLevel?.toUpperCase())} | ${esc(doc.serviceModel?.toUpperCase())}</span>`
    : "";

  const classificationLabel = doc.fedrampCompliant ? "CONTROLLED UNCLASSIFIED INFORMATION (CUI)" : "CONFIDENTIAL — FOR AUTHORIZED RECIPIENTS ONLY";

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${esc(doc.title)} — Rules of Engagement</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

  :root {
    --brand-primary: #0a1628;
    --brand-accent: #14b8a6;
    --brand-dark: #020617;
    --text-primary: #0f172a;
    --text-secondary: #475569;
    --text-muted: #94a3b8;
    --border: #e2e8f0;
    --bg-light: #f8fafc;
    --bg-section: #f1f5f9;
    --danger: #dc2626;
    --warning: #d97706;
    --success: #16a34a;
  }

  * { margin: 0; padding: 0; box-sizing: border-box; }

  @page {
    size: letter;
    margin: 1in 0.75in;
    @top-center { content: "${classificationLabel}"; font-size: 8pt; color: #dc2626; font-family: 'Inter', sans-serif; }
    @bottom-left { content: "${esc(doc.title)} v${esc(doc.version)}"; font-size: 7pt; color: #94a3b8; font-family: 'Inter', sans-serif; }
    @bottom-right { content: "Page " counter(page) " of " counter(pages); font-size: 7pt; color: #94a3b8; font-family: 'Inter', sans-serif; }
  }

  body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    font-size: 10pt;
    line-height: 1.6;
    color: var(--text-primary);
    background: white;
  }

  /* ─── Cover Page ─────────────────────────────────────────── */
  .cover-page {
    page-break-after: always;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    text-align: center;
    padding: 2rem;
    position: relative;
  }
  .cover-classification {
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    background: var(--danger);
    color: white;
    font-size: 9pt;
    font-weight: 600;
    padding: 6px 0;
    letter-spacing: 2px;
    text-transform: uppercase;
  }
  .cover-logo {
    width: 180px;
    margin-bottom: 2rem;
  }
  .cover-title {
    font-size: 28pt;
    font-weight: 700;
    color: var(--brand-primary);
    margin-bottom: 0.5rem;
    line-height: 1.2;
  }
  .cover-subtitle {
    font-size: 14pt;
    font-weight: 400;
    color: var(--text-secondary);
    margin-bottom: 2rem;
  }
  .cover-meta {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1rem;
    text-align: left;
    max-width: 500px;
    margin: 2rem auto;
    font-size: 9pt;
  }
  .cover-meta dt { font-weight: 600; color: var(--text-secondary); text-transform: uppercase; font-size: 7pt; letter-spacing: 1px; }
  .cover-meta dd { color: var(--text-primary); margin-bottom: 0.75rem; }
  .fedramp-badge {
    display: inline-block;
    background: var(--brand-accent);
    color: white;
    font-size: 8pt;
    font-weight: 600;
    padding: 4px 12px;
    border-radius: 4px;
    letter-spacing: 1px;
    margin-top: 1rem;
  }
  .cover-footer {
    position: absolute;
    bottom: 2rem;
    font-size: 8pt;
    color: var(--text-muted);
  }

  /* ─── Document Control ──────────────────────────────────── */
  .doc-control { page-break-after: always; }
  .doc-control h2 { font-size: 16pt; margin-bottom: 1rem; color: var(--brand-primary); border-bottom: 2px solid var(--brand-accent); padding-bottom: 0.5rem; }
  .control-table { width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: 9pt; }
  .control-table th { background: var(--bg-section); text-align: left; padding: 8px 12px; font-weight: 600; border: 1px solid var(--border); }
  .control-table td { padding: 8px 12px; border: 1px solid var(--border); }

  /* ─── TOC ────────────────────────────────────────────────── */
  .toc { page-break-after: always; }
  .toc h2 { font-size: 18pt; margin-bottom: 1.5rem; color: var(--brand-primary); }
  .toc-list { list-style: none; }
  .toc-list li { padding: 6px 0; border-bottom: 1px dotted var(--border); display: flex; justify-content: space-between; }
  .toc-list li .toc-num { font-weight: 600; color: var(--brand-accent); margin-right: 0.75rem; min-width: 2rem; }
  .toc-list li .toc-title { flex: 1; }
  .toc-list li .toc-page { color: var(--text-muted); font-size: 9pt; }

  /* ─── Sections ──────────────────────────────────────────── */
  .section { page-break-inside: avoid; margin-bottom: 2rem; }
  .section-header {
    font-size: 16pt;
    font-weight: 700;
    color: var(--brand-primary);
    border-bottom: 3px solid var(--brand-accent);
    padding-bottom: 0.5rem;
    margin-bottom: 1rem;
    page-break-after: avoid;
  }
  .section-num { color: var(--brand-accent); margin-right: 0.5rem; }
  .subsection { margin: 1rem 0; }
  .subsection h3 { font-size: 12pt; font-weight: 600; color: var(--brand-primary); margin-bottom: 0.5rem; }
  .subsection h4 { font-size: 10pt; font-weight: 600; color: var(--text-secondary); margin-bottom: 0.25rem; }
  .subsection p { margin-bottom: 0.5rem; color: var(--text-primary); }

  /* ─── Tables ────────────────────────────────────────────── */
  table.data-table { width: 100%; border-collapse: collapse; margin: 0.75rem 0; font-size: 9pt; }
  table.data-table thead th { background: var(--brand-primary); color: white; padding: 8px 10px; text-align: left; font-weight: 600; font-size: 8pt; text-transform: uppercase; letter-spacing: 0.5px; }
  table.data-table tbody td { padding: 7px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
  table.data-table tbody tr:nth-child(even) { background: var(--bg-light); }
  table.data-table tbody tr:hover { background: #e0f2fe; }

  /* ─── Info Boxes ────────────────────────────────────────── */
  .info-box { background: var(--bg-light); border-left: 4px solid var(--brand-accent); padding: 12px 16px; margin: 0.75rem 0; border-radius: 0 4px 4px 0; }
  .warning-box { background: #fffbeb; border-left: 4px solid var(--warning); padding: 12px 16px; margin: 0.75rem 0; border-radius: 0 4px 4px 0; }
  .danger-box { background: #fef2f2; border-left: 4px solid var(--danger); padding: 12px 16px; margin: 0.75rem 0; border-radius: 0 4px 4px 0; }
  .box-title { font-weight: 600; font-size: 9pt; margin-bottom: 4px; }

  /* ─── Signature Blocks ──────────────────────────────────── */
  .sig-block { border: 1px solid var(--border); padding: 1.5rem; margin: 1rem 0; page-break-inside: avoid; }
  .sig-block .sig-role { font-size: 8pt; text-transform: uppercase; letter-spacing: 1px; color: var(--brand-accent); font-weight: 600; margin-bottom: 0.5rem; }
  .sig-line { border-bottom: 1px solid var(--text-primary); height: 40px; margin: 0.5rem 0; }
  .sig-meta { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-top: 0.5rem; }
  .sig-meta .sig-field { font-size: 8pt; }
  .sig-meta .sig-field-label { color: var(--text-muted); text-transform: uppercase; font-size: 7pt; letter-spacing: 0.5px; }
  .sig-signed { background: #f0fdf4; border: 1px solid #86efac; padding: 8px 12px; border-radius: 4px; font-size: 8pt; color: var(--success); margin-top: 0.5rem; }

  /* ─── Badges ────────────────────────────────────────────── */
  .badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 8pt; font-weight: 600; }
  .badge-required { background: #fee2e2; color: var(--danger); }
  .badge-optional { background: #e0f2fe; color: #0369a1; }
  .badge-enabled { background: #dcfce7; color: var(--success); }
  .badge-fedramp { background: #dbeafe; color: #1d4ed8; }
  .badge-critical { background: #fee2e2; color: var(--danger); }
  .badge-high { background: #ffedd5; color: #c2410c; }
  .badge-medium { background: #fef9c3; color: #a16207; }
  .badge-low { background: #dcfce7; color: var(--success); }

  /* ─── Utilities ─────────────────────────────────────────── */
  .text-muted { color: var(--text-muted); }
  .text-sm { font-size: 9pt; }
  .text-xs { font-size: 8pt; }
  .mt-1 { margin-top: 0.5rem; }
  .mt-2 { margin-top: 1rem; }
  .mb-1 { margin-bottom: 0.5rem; }
  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; }
  .mono { font-family: 'JetBrains Mono', monospace; font-size: 9pt; }
  .page-break { page-break-before: always; }

  @media print {
    body { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .no-print { display: none; }
  }
</style>
</head>
<body>

<!-- ═══════════════════════════════════════════════════════════
     COVER PAGE
     ═══════════════════════════════════════════════════════════ -->
<div class="cover-page">
  <div class="cover-classification">${classificationLabel}</div>
  <div style="margin-top: 3rem;">
    <div style="font-size: 11pt; font-weight: 600; color: var(--brand-accent); letter-spacing: 3px; text-transform: uppercase; margin-bottom: 0.5rem;">ACE C3 — AceofCloud</div>
    <div class="cover-title">Rules of Engagement</div>
    <div class="cover-subtitle">${esc(doc.title)}</div>
    ${fedrampBadge}
  </div>
  <dl class="cover-meta">
    <div><dt>Organization</dt><dd>${esc(doc.organizationName) || "TBD"}</dd></div>
    <div><dt>Testing Firm</dt><dd>${esc(doc.testingFirmName) || "ACE C3 — AceofCloud"}</dd></div>
    <div><dt>Document Version</dt><dd>${esc(doc.version)}</dd></div>
    <div><dt>Status</dt><dd>${esc(doc.status?.toUpperCase())}</dd></div>
    <div><dt>Test Period</dt><dd>${formatDate(doc.testScheduleStart)} — ${formatDate(doc.testScheduleEnd)}</dd></div>
    <div><dt>Date Prepared</dt><dd>${formatDate(doc.createdAt)}</dd></div>
    ${doc.fedrampCompliant ? `<div><dt>FedRAMP Impact</dt><dd>${esc(doc.fedrampImpactLevel?.toUpperCase())}</dd></div>
    <div><dt>Service Model</dt><dd>${esc(doc.serviceModel?.toUpperCase())}</dd></div>` : ""}
  </dl>
  <div class="cover-footer">
    Prepared by Harrison Cook — AceofCloud &bull; <a href="https://aceofcloud.com">aceofcloud.com</a><br>
    This document contains confidential information. Unauthorized distribution is prohibited.
  </div>
</div>

<!-- ═══════════════════════════════════════════════════════════
     DOCUMENT CONTROL
     ═══════════════════════════════════════════════════════════ -->
<div class="doc-control">
  <h2>Document Control</h2>

  <h3 class="mt-2">Revision History</h3>
  <table class="control-table">
    <thead><tr><th>Version</th><th>Date</th><th>Author</th><th>Description</th></tr></thead>
    <tbody>
      <tr><td>${esc(doc.version)}</td><td>${formatDate(doc.createdAt)}</td><td>Harrison Cook</td><td>Initial draft</td></tr>
      ${doc.approvedAt ? `<tr><td>${esc(doc.version)}</td><td>${formatDate(doc.approvedAt)}</td><td>Authorizing Official</td><td>Approved</td></tr>` : ""}
    </tbody>
  </table>

  <h3 class="mt-2">Distribution List</h3>
  <table class="control-table">
    <thead><tr><th>Name</th><th>Role</th><th>Organization</th><th>Email</th></tr></thead>
    <tbody>
      ${personnel.map((p: any) => `<tr><td>${esc(p.name)}</td><td>${esc(ROLE_LABELS[p.role] || p.role)}</td><td>${esc(p.organization)}</td><td>${esc(p.email)}</td></tr>`).join("")}
      ${personnel.length === 0 ? `<tr><td colspan="4" class="text-muted">No personnel assigned</td></tr>` : ""}
    </tbody>
  </table>

  <div class="warning-box mt-2">
    <div class="box-title">Handling Instructions</div>
    <p class="text-sm">This document is classified as ${classificationLabel}. It must be stored on encrypted media, transmitted only via encrypted channels, and destroyed in accordance with the evidence destruction procedures defined in Section 9 of this document.</p>
  </div>
</div>

<!-- ═══════════════════════════════════════════════════════════
     TABLE OF CONTENTS
     ═══════════════════════════════════════════════════════════ -->
<div class="toc">
  <h2>Table of Contents</h2>
  <ul class="toc-list">
    <li><span class="toc-num">1</span><span class="toc-title">Authorization &amp; Purpose</span></li>
    <li><span class="toc-num">2</span><span class="toc-title">Scope of Assessment</span></li>
    <li><span class="toc-num">&nbsp;&nbsp;2.1</span><span class="toc-title">In-Scope Assets</span></li>
    <li><span class="toc-num">&nbsp;&nbsp;2.2</span><span class="toc-title">Out-of-Scope Assets</span></li>
    <li><span class="toc-num">&nbsp;&nbsp;2.3</span><span class="toc-title">Cloud Environments</span></li>
    <li><span class="toc-num">3</span><span class="toc-title">Testing Methodology</span></li>
    <li><span class="toc-num">&nbsp;&nbsp;3.1</span><span class="toc-title">Testing Types</span></li>
    <li><span class="toc-num">&nbsp;&nbsp;3.2</span><span class="toc-title">Attack Vectors</span></li>
    <li><span class="toc-num">&nbsp;&nbsp;3.3</span><span class="toc-title">Testing Permissions &amp; Restrictions</span></li>
    <li><span class="toc-num">4</span><span class="toc-title">Schedule &amp; Logistics</span></li>
    <li><span class="toc-num">5</span><span class="toc-title">Communication Plan</span></li>
    <li><span class="toc-num">&nbsp;&nbsp;5.1</span><span class="toc-title">Incident Response Procedures</span></li>
    <li><span class="toc-num">&nbsp;&nbsp;5.2</span><span class="toc-title">Emergency Halt Criteria</span></li>
    <li><span class="toc-num">6</span><span class="toc-title">Data Handling &amp; Evidence</span></li>
    <li><span class="toc-num">7</span><span class="toc-title">Legal &amp; Compliance</span></li>
    <li><span class="toc-num">8</span><span class="toc-title">Report Deliverables</span></li>
    <li><span class="toc-num">9</span><span class="toc-title">Personnel &amp; Points of Contact</span></li>
    <li><span class="toc-num">10</span><span class="toc-title">Authorization Signatures</span></li>
    <li><span class="toc-num">A</span><span class="toc-title">Appendix: Compliance Framework References</span></li>
  </ul>
</div>

<!-- ═══════════════════════════════════════════════════════════
     SECTION 1: AUTHORIZATION & PURPOSE
     ═══════════════════════════════════════════════════════════ -->
<div class="section">
  <h2 class="section-header"><span class="section-num">1.</span> Authorization &amp; Purpose</h2>

  <div class="subsection">
    <h3>1.1 Purpose</h3>
    <p>${esc(doc.purpose) || "This Rules of Engagement (RoE) document establishes the terms, conditions, scope, and limitations for the authorized security assessment."}</p>
  </div>

  <div class="subsection">
    <h3>1.2 Parties</h3>
    <div class="grid-2">
      <div class="info-box">
        <div class="box-title">Organization Under Test</div>
        <p><strong>${esc(doc.organizationName) || "TBD"}</strong></p>
        ${doc.organizationAddress ? `<p class="text-sm text-muted">${esc(doc.organizationAddress)}</p>` : ""}
      </div>
      <div class="info-box">
        <div class="box-title">Testing Firm</div>
        <p><strong>${esc(doc.testingFirmName) || "ACE C3 — AceofCloud"}</strong></p>
        ${doc.testingFirmAddress ? `<p class="text-sm text-muted">${esc(doc.testingFirmAddress)}</p>` : ""}
      </div>
    </div>
  </div>

  ${doc.assumptions ? `<div class="subsection"><h3>1.3 Assumptions</h3><p>${esc(doc.assumptions)}</p></div>` : ""}
  ${doc.limitations ? `<div class="subsection"><h3>1.4 Limitations</h3><p>${esc(doc.limitations)}</p></div>` : ""}
  ${doc.risks ? `<div class="subsection"><h3>1.5 Risks</h3><div class="warning-box"><p>${esc(doc.risks)}</p></div></div>` : ""}
</div>

<!-- ═══════════════════════════════════════════════════════════
     SECTION 2: SCOPE
     ═══════════════════════════════════════════════════════════ -->
<div class="section page-break">
  <h2 class="section-header"><span class="section-num">2.</span> Scope of Assessment</h2>

  ${doc.scopeDescription ? `<div class="subsection"><p>${esc(doc.scopeDescription)}</p></div>` : ""}

  <div class="subsection">
    <h3>2.1 In-Scope Assets</h3>

    ${inScopeIpRanges.length > 0 ? `
    <h4 class="mt-1">IP Ranges</h4>
    <table class="data-table">
      <thead><tr><th>CIDR</th><th>Description</th><th>VLAN</th><th>Location</th></tr></thead>
      <tbody>${inScopeIpRanges.map((r: any) => `<tr><td class="mono">${esc(r.cidr)}</td><td>${esc(r.description)}</td><td>${esc(r.vlan)}</td><td>${esc(r.location)}</td></tr>`).join("")}</tbody>
    </table>` : ""}

    ${inScopeDomains.length > 0 ? `
    <h4 class="mt-1">Domains</h4>
    <table class="data-table">
      <thead><tr><th>Domain</th><th>Include Subdomains</th><th>Description</th></tr></thead>
      <tbody>${inScopeDomains.map((d: any) => `<tr><td class="mono">${esc(d.domain)}</td><td>${boolLabel(d.includeSubdomains)}</td><td>${esc(d.description)}</td></tr>`).join("")}</tbody>
    </table>` : ""}

    ${inScopeApplications.length > 0 ? `
    <h4 class="mt-1">Applications</h4>
    <table class="data-table">
      <thead><tr><th>Name</th><th>URL</th><th>Type</th><th>Auth Required</th><th>Description</th></tr></thead>
      <tbody>${inScopeApplications.map((a: any) => `<tr><td>${esc(a.name)}</td><td class="mono">${esc(a.url)}</td><td>${esc(a.type)}</td><td>${boolLabel(a.authRequired)}</td><td>${esc(a.description)}</td></tr>`).join("")}</tbody>
    </table>` : ""}

    ${inScopeAssets.length > 0 ? `
    <h4 class="mt-1">Systems &amp; Hosts</h4>
    <table class="data-table">
      <thead><tr><th>Name</th><th>Type</th><th>IP</th><th>Hostname</th><th>OS</th><th>Criticality</th></tr></thead>
      <tbody>${inScopeAssets.map((a: any) => `<tr><td>${esc(a.name)}</td><td>${esc(a.type)}</td><td class="mono">${esc(a.ipAddress)}</td><td class="mono">${esc(a.hostname)}</td><td>${esc(a.os)}</td><td><span class="badge badge-${a.criticality || 'low'}">${esc(a.criticality?.toUpperCase())}</span></td></tr>`).join("")}</tbody>
    </table>` : ""}
  </div>

  <div class="subsection">
    <h3>2.2 Out-of-Scope Assets</h3>
    <div class="danger-box">
      <div class="box-title">DO NOT TEST — The following assets are explicitly excluded from testing</div>
    </div>

    ${outOfScopeIpRanges.length > 0 ? `
    <table class="data-table">
      <thead><tr><th>CIDR</th><th>Description</th><th>Reason</th></tr></thead>
      <tbody>${outOfScopeIpRanges.map((r: any) => `<tr><td class="mono">${esc(r.cidr)}</td><td>${esc(r.description)}</td><td>${esc(r.location)}</td></tr>`).join("")}</tbody>
    </table>` : ""}

    ${outOfScopeDomains.length > 0 ? `
    <table class="data-table">
      <thead><tr><th>Domain</th><th>Description</th></tr></thead>
      <tbody>${outOfScopeDomains.map((d: any) => `<tr><td class="mono">${esc(d.domain)}</td><td>${esc(d.description)}</td></tr>`).join("")}</tbody>
    </table>` : ""}

    ${outOfScopeAssets.length > 0 ? `
    <table class="data-table">
      <thead><tr><th>Name</th><th>Type</th><th>IP</th><th>Reason</th></tr></thead>
      <tbody>${outOfScopeAssets.map((a: any) => `<tr><td>${esc(a.name)}</td><td>${esc(a.type)}</td><td class="mono">${esc(a.ipAddress)}</td><td>${esc(a.description)}</td></tr>`).join("")}</tbody>
    </table>` : ""}

    ${outOfScopeIpRanges.length === 0 && outOfScopeDomains.length === 0 && outOfScopeAssets.length === 0 ? `<p class="text-muted text-sm">No out-of-scope exclusions defined.</p>` : ""}
  </div>

  ${cloudEnvironments.length > 0 ? `
  <div class="subsection">
    <h3>2.3 Cloud Environments</h3>
    <table class="data-table">
      <thead><tr><th>Provider</th><th>Account ID</th><th>Region</th><th>Services</th><th>Description</th></tr></thead>
      <tbody>${cloudEnvironments.map((c: any) => `<tr><td>${esc(c.provider?.toUpperCase())}</td><td class="mono">${esc(c.accountId)}</td><td>${esc(c.region)}</td><td>${(c.services || []).map((s: string) => esc(s)).join(", ")}</td><td>${esc(c.description)}</td></tr>`).join("")}</tbody>
    </table>
  </div>` : ""}
</div>

<!-- ═══════════════════════════════════════════════════════════
     SECTION 3: TESTING METHODOLOGY
     ═══════════════════════════════════════════════════════════ -->
<div class="section page-break">
  <h2 class="section-header"><span class="section-num">3.</span> Testing Methodology</h2>

  <div class="subsection">
    <h3>3.1 Authorized Testing Types</h3>
    <p class="text-sm mb-1">The following testing methodologies have been authorized for this engagement, aligned with NIST SP 800-115 and PTES standards.</p>
    <table class="data-table">
      <thead><tr><th>Testing Type</th><th>Category</th><th>Description</th></tr></thead>
      <tbody>
        ${enabledTypes.map((t: any) => `<tr><td><strong>${esc(t.name)}</strong></td><td><span class="badge badge-enabled">${esc(t.category?.replace("_", " ").toUpperCase())}</span></td><td>${esc(t.description)}</td></tr>`).join("")}
        ${enabledTypes.length === 0 ? `<tr><td colspan="3" class="text-muted">No testing types selected</td></tr>` : ""}
      </tbody>
    </table>
  </div>

  <div class="subsection">
    <h3>3.2 Attack Vectors</h3>
    ${doc.fedrampCompliant ? `<div class="info-box"><div class="box-title">FedRAMP Requirement</div><p class="text-sm">Per FedRAMP penetration testing guidance, all FedRAMP-required attack vectors must be tested for the ${esc(doc.fedrampImpactLevel?.toUpperCase())} impact level.</p></div>` : ""}
    <table class="data-table">
      <thead><tr><th>Attack Vector</th><th>Description</th><th>Status</th></tr></thead>
      <tbody>
        ${enabledVectors.map((v: any) => `<tr><td><strong>${esc(v.name)}</strong></td><td>${esc(v.description)}</td><td>${v.fedrampRequired ? '<span class="badge badge-fedramp">FedRAMP Required</span>' : '<span class="badge badge-enabled">Enabled</span>'}</td></tr>`).join("")}
        ${enabledVectors.length === 0 ? `<tr><td colspan="3" class="text-muted">No attack vectors selected</td></tr>` : ""}
      </tbody>
    </table>
  </div>

  <div class="subsection">
    <h3>3.3 Testing Permissions &amp; Restrictions</h3>
    <table class="data-table">
      <thead><tr><th>Permission</th><th>Status</th></tr></thead>
      <tbody>
        <tr><td>Denial of Service (DoS) Testing</td><td>${boolLabel(doc.dosTestingAllowed)}</td></tr>
        <tr><td>Physical Security Testing</td><td>${boolLabel(doc.physicalTestingAllowed)}</td></tr>
        <tr><td>Wireless Security Testing</td><td>${boolLabel(doc.wirelessTestingAllowed)}</td></tr>
        <tr><td>Social Engineering</td><td>${boolLabel(doc.socialEngineeringAllowed)}</td></tr>
        <tr><td>Credentialed Testing</td><td>${boolLabel(doc.credentialedTesting)}</td></tr>
        <tr><td>File Modification on Target Systems</td><td>${boolLabel(doc.fileModificationAllowed)}</td></tr>
        <tr><td>Software Installation on Target Systems</td><td>${boolLabel(doc.fileInstallationAllowed)}</td></tr>
        <tr><td>Lateral Movement / Pivoting</td><td>${boolLabel(doc.pivotingAllowed)}</td></tr>
        <tr><td>Data Exfiltration (Simulated)</td><td>${boolLabel(doc.exfiltrationAllowed)}</td></tr>
        <tr><td>Persistence Mechanisms</td><td>${boolLabel(doc.persistenceAllowed)}</td></tr>
        <tr><td>Shunning / Active Defense Response</td><td>${esc(doc.shunningPolicy === "notify_first" ? "Notify First" : doc.shunningPolicy === "allowed" ? "Allowed" : "Not Allowed")}</td></tr>
      </tbody>
    </table>
  </div>
</div>

<!-- ═══════════════════════════════════════════════════════════
     SECTION 4: SCHEDULE & LOGISTICS
     ═══════════════════════════════════════════════════════════ -->
<div class="section page-break">
  <h2 class="section-header"><span class="section-num">4.</span> Schedule &amp; Logistics</h2>

  <div class="grid-2">
    <div class="info-box">
      <div class="box-title">Test Period</div>
      <p><strong>${formatDate(doc.testScheduleStart)}</strong> through <strong>${formatDate(doc.testScheduleEnd)}</strong></p>
    </div>
    <div class="info-box">
      <div class="box-title">Testing Window</div>
      <p><strong>${formatTime(doc.testingWindowStart)}</strong> — <strong>${formatTime(doc.testingWindowEnd)}</strong> (${esc(doc.testTimezone)})</p>
    </div>
  </div>

  <div class="subsection mt-2">
    <h3>Authorized Testing Days</h3>
    <p>${testingDays.map((d: string) => d.charAt(0).toUpperCase() + d.slice(1)).join(", ") || "TBD"}</p>
  </div>

  <div class="subsection">
    <h3>Logistics</h3>
    <table class="data-table">
      <thead><tr><th>Item</th><th>Details</th></tr></thead>
      <tbody>
        <tr><td>Remote Testing Allowed</td><td>${boolLabel(doc.remoteTestingAllowed)}</td></tr>
        <tr><td>VPN Required</td><td>${boolLabel(doc.vpnRequired)}</td></tr>
        <tr><td>Badge/Escort Required</td><td>${boolLabel(doc.badgeEscortRequired)}</td></tr>
        <tr><td>Timezone</td><td>${esc(doc.testTimezone)}</td></tr>
      </tbody>
    </table>
  </div>
</div>

<!-- ═══════════════════════════════════════════════════════════
     SECTION 5: COMMUNICATION PLAN
     ═══════════════════════════════════════════════════════════ -->
<div class="section page-break">
  <h2 class="section-header"><span class="section-num">5.</span> Communication Plan</h2>

  <div class="grid-2">
    <div class="info-box">
      <div class="box-title">Communication Frequency</div>
      <p>${esc(doc.communicationFrequency?.replace("-", " ").replace(/\b\w/g, (c: string) => c.toUpperCase()))}</p>
    </div>
    <div class="info-box">
      <div class="box-title">Primary Method</div>
      <p>${esc(doc.communicationMethod?.replace("_", " ").replace(/\b\w/g, (c: string) => c.toUpperCase()))}</p>
    </div>
  </div>

  <div class="subsection mt-2">
    <h3>5.1 Incident Response Procedures</h3>
    <p>${esc(doc.incidentResponseProcedure) || "See standard incident response procedures."}</p>
  </div>

  <div class="subsection">
    <h3>5.2 Emergency Halt Criteria</h3>
    <div class="danger-box">
      <div class="box-title">Testing shall be immediately halted if any of the following conditions occur:</div>
      <p class="text-sm">${esc(doc.emergencyHaltCriteria) || "Standard halt criteria apply."}</p>
    </div>
  </div>

  ${doc.resumptionProcedure ? `
  <div class="subsection">
    <h3>5.3 Resumption Procedure</h3>
    <p>${esc(doc.resumptionProcedure)}</p>
  </div>` : ""}

  ${doc.criticalFindingNotification ? `
  <div class="subsection">
    <h3>5.4 Critical Finding Notification</h3>
    <div class="warning-box"><p class="text-sm">${esc(doc.criticalFindingNotification)}</p></div>
  </div>` : ""}
</div>

<!-- ═══════════════════════════════════════════════════════════
     SECTION 6: DATA HANDLING & EVIDENCE
     ═══════════════════════════════════════════════════════════ -->
<div class="section page-break">
  <h2 class="section-header"><span class="section-num">6.</span> Data Handling &amp; Evidence</h2>

  <div class="subsection">
    <h3>6.1 Data Handling Procedures</h3>
    <p>${esc(doc.dataHandlingProcedure) || "Standard data handling procedures apply."}</p>
  </div>

  <div class="subsection">
    <h3>6.2 PII/PHI Handling Policy</h3>
    <p>${esc(doc.piiHandlingPolicy) || "Standard PII handling policy applies."}</p>
  </div>

  <div class="subsection">
    <h3>6.3 Evidence Management</h3>
    <table class="data-table">
      <thead><tr><th>Policy</th><th>Details</th></tr></thead>
      <tbody>
        <tr><td>Retention Period</td><td><strong>${doc.evidenceRetentionDays || 90} days</strong></td></tr>
        <tr><td>Encryption Required</td><td>${boolLabel(doc.evidenceEncryptionRequired)}</td></tr>
        <tr><td>Destruction Method</td><td>${esc(doc.evidenceDestructionMethod?.replace("_", " ").replace(/\b\w/g, (c: string) => c.toUpperCase()))}</td></tr>
      </tbody>
    </table>
  </div>
</div>

<!-- ═══════════════════════════════════════════════════════════
     SECTION 7: LEGAL & COMPLIANCE
     ═══════════════════════════════════════════════════════════ -->
<div class="section page-break">
  <h2 class="section-header"><span class="section-num">7.</span> Legal &amp; Compliance</h2>

  <div class="subsection">
    <table class="data-table">
      <thead><tr><th>Item</th><th>Details</th></tr></thead>
      <tbody>
        ${doc.legalJurisdiction ? `<tr><td>Legal Jurisdiction</td><td>${esc(doc.legalJurisdiction)}</td></tr>` : ""}
        <tr><td>NDA Required</td><td>${boolLabel(doc.ndaRequired)}</td></tr>
        ${doc.ndaReference ? `<tr><td>NDA Reference</td><td>${esc(doc.ndaReference)}</td></tr>` : ""}
      </tbody>
    </table>
  </div>

  ${doc.liabilityWaiver ? `
  <div class="subsection">
    <h3>7.1 Liability Waiver</h3>
    <p>${esc(doc.liabilityWaiver)}</p>
  </div>` : ""}

  ${complianceFrameworks.length > 0 ? `
  <div class="subsection">
    <h3>7.2 Applicable Compliance Frameworks</h3>
    <div style="display: flex; flex-wrap: wrap; gap: 6px;">
      ${complianceFrameworks.map((f: string) => `<span class="badge badge-fedramp">${esc(f)}</span>`).join("")}
    </div>
  </div>` : ""}

  ${thirdPartyAgreements.length > 0 ? `
  <div class="subsection">
    <h3>7.3 Third-Party Agreements</h3>
    <table class="data-table">
      <thead><tr><th>Agreement</th><th>Description</th></tr></thead>
      <tbody>${thirdPartyAgreements.map((a: any) => `<tr><td>${esc(a.name)}</td><td>${esc(a.description)}</td></tr>`).join("")}</tbody>
    </table>
  </div>` : ""}
</div>

<!-- ═══════════════════════════════════════════════════════════
     SECTION 8: REPORT DELIVERABLES
     ═══════════════════════════════════════════════════════════ -->
<div class="section page-break">
  <h2 class="section-header"><span class="section-num">8.</span> Report Deliverables</h2>

  <div class="subsection">
    <h3>8.1 Required Deliverables</h3>
    <table class="data-table">
      <thead><tr><th>Deliverable</th><th>Description</th></tr></thead>
      <tbody>
        ${requiredDeliverables.map((d: any) => `<tr><td><strong>${esc(d.name)}</strong> <span class="badge badge-required">Required</span></td><td>${esc(d.description)}</td></tr>`).join("")}
      </tbody>
    </table>
  </div>

  ${optionalDeliverables.length > 0 ? `
  <div class="subsection">
    <h3>8.2 Optional Deliverables</h3>
    <table class="data-table">
      <thead><tr><th>Deliverable</th><th>Description</th></tr></thead>
      <tbody>
        ${optionalDeliverables.map((d: any) => `<tr><td>${esc(d.name)} <span class="badge badge-optional">Optional</span></td><td>${esc(d.description)}</td></tr>`).join("")}
      </tbody>
    </table>
  </div>` : ""}

  <div class="subsection">
    <h3>8.3 Reporting Schedule</h3>
    <p>Report frequency: <strong>${esc(doc.reportFrequency?.replace("_", " ").replace(/\b\w/g, (c: string) => c.toUpperCase()))}</strong></p>
  </div>
</div>

<!-- ═══════════════════════════════════════════════════════════
     SECTION 9: PERSONNEL & POINTS OF CONTACT
     ═══════════════════════════════════════════════════════════ -->
<div class="section page-break">
  <h2 class="section-header"><span class="section-num">9.</span> Personnel &amp; Points of Contact</h2>

  <table class="data-table">
    <thead><tr><th>Name</th><th>Role</th><th>Organization</th><th>Email</th><th>Phone</th><th>Primary</th></tr></thead>
    <tbody>
      ${personnel.map((p: any) => `<tr><td><strong>${esc(p.name)}</strong></td><td>${esc(ROLE_LABELS[p.role] || p.role)}</td><td>${esc(p.organization)}</td><td>${esc(p.email)}</td><td>${esc(p.phone)}</td><td>${p.isPrimary ? '<span class="badge badge-enabled">Primary</span>' : ""}</td></tr>`).join("")}
      ${personnel.length === 0 ? `<tr><td colspan="6" class="text-muted">No personnel assigned</td></tr>` : ""}
    </tbody>
  </table>
</div>

<!-- ═══════════════════════════════════════════════════════════
     SECTION 10: AUTHORIZATION SIGNATURES
     ═══════════════════════════════════════════════════════════ -->
<div class="section page-break">
  <h2 class="section-header"><span class="section-num">10.</span> Authorization Signatures</h2>

  <p class="mb-1">By signing below, the undersigned parties acknowledge that they have read, understood, and agree to the terms and conditions set forth in this Rules of Engagement document. This authorization permits the testing firm to conduct the security assessment as described herein.</p>

  ${signatures.length > 0 ? signatures.map((s: any) => `
  <div class="sig-block">
    <div class="sig-role">${esc(SIGNER_ROLE_LABELS[s.signerRole] || s.signerRole)}</div>
    ${s.signatureData ? `<div class="sig-signed">✓ Digitally signed by ${esc(s.signerName)} on ${formatDate(s.signedAt)}</div>` : `<div class="sig-line"></div>`}
    <div class="sig-meta">
      <div class="sig-field"><div class="sig-field-label">Printed Name</div><div>${esc(s.signerName)}</div></div>
      <div class="sig-field"><div class="sig-field-label">Title</div><div>${esc(s.signerTitle)}</div></div>
      <div class="sig-field"><div class="sig-field-label">Organization</div><div>${esc(s.signerOrganization)}</div></div>
      <div class="sig-field"><div class="sig-field-label">Date</div><div>${s.signedAt ? formatDate(s.signedAt) : "________________"}</div></div>
    </div>
  </div>`).join("") : `
  <!-- Empty signature blocks for manual signing -->
  <div class="sig-block">
    <div class="sig-role">Customer Executive / Authorizing Official</div>
    <div class="sig-line"></div>
    <div class="sig-meta">
      <div class="sig-field"><div class="sig-field-label">Printed Name</div><div>________________________________</div></div>
      <div class="sig-field"><div class="sig-field-label">Title</div><div>________________________________</div></div>
      <div class="sig-field"><div class="sig-field-label">Organization</div><div>________________________________</div></div>
      <div class="sig-field"><div class="sig-field-label">Date</div><div>________________</div></div>
    </div>
  </div>
  <div class="sig-block">
    <div class="sig-role">Customer Technical Lead</div>
    <div class="sig-line"></div>
    <div class="sig-meta">
      <div class="sig-field"><div class="sig-field-label">Printed Name</div><div>________________________________</div></div>
      <div class="sig-field"><div class="sig-field-label">Title</div><div>________________________________</div></div>
      <div class="sig-field"><div class="sig-field-label">Organization</div><div>________________________________</div></div>
      <div class="sig-field"><div class="sig-field-label">Date</div><div>________________</div></div>
    </div>
  </div>
  <div class="sig-block">
    <div class="sig-role">Testing Lead — ACE C3</div>
    <div class="sig-line"></div>
    <div class="sig-meta">
      <div class="sig-field"><div class="sig-field-label">Printed Name</div><div>________________________________</div></div>
      <div class="sig-field"><div class="sig-field-label">Title</div><div>________________________________</div></div>
      <div class="sig-field"><div class="sig-field-label">Organization</div><div>ACE C3 — AceofCloud</div></div>
      <div class="sig-field"><div class="sig-field-label">Date</div><div>________________</div></div>
    </div>
  </div>`}
</div>

<!-- ═══════════════════════════════════════════════════════════
     APPENDIX A: COMPLIANCE FRAMEWORK REFERENCES
     ═══════════════════════════════════════════════════════════ -->
<div class="section page-break">
  <h2 class="section-header"><span class="section-num">A.</span> Appendix: Compliance Framework References</h2>

  <table class="data-table">
    <thead><tr><th>Framework</th><th>Relevance to Penetration Testing</th></tr></thead>
    <tbody>
      <tr><td><strong>NIST SP 800-115</strong></td><td>Technical Guide to Information Security Testing and Assessment — primary reference for RoE structure and testing methodology</td></tr>
      <tr><td><strong>NIST SP 800-53</strong></td><td>Security and Privacy Controls — CA-8 (Penetration Testing) control family</td></tr>
      <tr><td><strong>FedRAMP</strong></td><td>Federal Risk and Authorization Management Program — requires annual penetration testing for cloud service providers</td></tr>
      <tr><td><strong>PTES</strong></td><td>Penetration Testing Execution Standard — comprehensive methodology for scoping and executing penetration tests</td></tr>
      <tr><td><strong>OSSTMM</strong></td><td>Open Source Security Testing Methodology Manual — operational security testing framework</td></tr>
      <tr><td><strong>PCI DSS</strong></td><td>Payment Card Industry Data Security Standard — Requirement 11.3 (Penetration Testing)</td></tr>
      <tr><td><strong>HIPAA</strong></td><td>Health Insurance Portability and Accountability Act — technical safeguard assessment requirements</td></tr>
      <tr><td><strong>SOC 2</strong></td><td>Service Organization Control — Trust Services Criteria for security testing</td></tr>
      <tr><td><strong>ISO 27001</strong></td><td>Information Security Management — Annex A.12.6 (Technical Vulnerability Management)</td></tr>
      <tr><td><strong>CMMC</strong></td><td>Cybersecurity Maturity Model Certification — assessment methodology for defense contractors</td></tr>
    </tbody>
  </table>

  <div class="info-box mt-2">
    <div class="box-title">Document Prepared By</div>
    <p class="text-sm">Harrison Cook — AceofCloud &bull; <a href="https://aceofcloud.com">https://aceofcloud.com</a></p>
    <p class="text-xs text-muted">This document was generated using the ACE C3 Rules of Engagement Builder. All content is based on industry best practices and applicable compliance frameworks.</p>
  </div>
</div>

</body>
</html>`;
}
