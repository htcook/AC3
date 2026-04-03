/**
 * Domain Intelligence EASM PDF Report Export
 * 
 * Generates a comprehensive, client-ready External Attack Surface Management
 * report from DI scan results. Designed for proposal delivery, client
 * presentations, and compliance documentation.
 * 
 * Sections:
 *   1. Cover Page — branded, domain, date, classification
 *   2. Executive Summary — risk gauge, key metrics, narrative
 *   3. Attack Surface Inventory — assets by type, criticality, risk band
 *   4. Domain Health & Blacklist Status — DNS, SSL, DNSBL, email security
 *   5. Breach & Credential Exposure — 1st-party vs 3rd-party classification
 *   6. Dark Web & Ransomware Intelligence — threat group attribution
 *   7. Vulnerability & Technology Landscape — CVEs, tech stack, WAF/NGFW
 *   8. Threat Actor Assessment — attributed groups, TTPs, IOCs
 *   9. Prioritized Recommendations — CARVER-ranked remediation actions
 *  10. Appendix — data sources, scan metadata, methodology
 */

// Dynamic imports to reduce bundle size
let _jsPDF: typeof import('jspdf').default | null = null;
let _autoTable: typeof import('jspdf-autotable').default | null = null;
async function loadPdfLibs() {
  if (!_jsPDF) _jsPDF = (await import('jspdf')).default;
  if (!_autoTable) _autoTable = (await import('jspdf-autotable')).default;
  return { jsPDF: _jsPDF, autoTable: _autoTable };
}

function dateStamp(): string {
  return new Date().toISOString().slice(0, 10).replace(/-/g, '');
}

function getRiskColor(band: string): [number, number, number] {
  switch (band?.toLowerCase()) {
    case 'critical': return [220, 38, 38];
    case 'high': return [234, 88, 12];
    case 'medium': return [202, 138, 4];
    case 'low': return [22, 163, 74];
    default: return [113, 113, 122];
  }
}

function getSeverityLabel(score: number): string {
  if (score >= 9) return 'Critical';
  if (score >= 7) return 'High';
  if (score >= 4) return 'Medium';
  return 'Low';
}

function truncate(str: string | null | undefined, max: number): string {
  if (!str) return '';
  return str.length > max ? str.substring(0, max - 3) + '...' : str;
}

/**
 * Export a comprehensive Domain Intelligence EASM PDF report
 */
export async function exportDiEasmReport(
  domain: string,
  scan: any,
): Promise<void> {
  const { jsPDF, autoTable } = await loadPdfLibs();
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 15;
  const contentWidth = pageWidth - margin * 2;

  // Extract data from scan
  const assets = scan.assets || [];
  const observations = scan.observations || [];
  const domainHealth = scan.domainHealth || {};
  const enrichment = scan.enrichment || {};
  const llmAnalysis = scan.llmAnalysis || {};
  const reputationEngine = scan.reputationEngine || {};
  const discoveryCoverage = scan.discoveryCoverage || {};
  const wafNgfw = scan.wafNgfwDetection || {};
  const crossModuleEnrichment = scan.crossModuleEnrichment || {};

  // Helper: add page with header
  function addSectionPage(title: string): number {
    doc.addPage();
    doc.setFillColor(15, 23, 42);
    doc.rect(0, 0, pageWidth, 22, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text(title, margin, 14);
    doc.setFontSize(7);
    doc.setTextColor(148, 163, 184);
    doc.text(domain, pageWidth - margin - doc.getTextWidth(domain), 14);
    return 30;
  }

  // Helper: check page break
  function checkPageBreak(y: number, needed: number = 30): number {
    if (y > pageHeight - needed) {
      doc.addPage();
      return 20;
    }
    return y;
  }

  // Helper: write wrapped text
  function writeText(text: string, x: number, y: number, maxWidth: number, fontSize: number = 9): number {
    doc.setFontSize(fontSize);
    const lines = doc.splitTextToSize(text, maxWidth);
    for (const line of lines) {
      y = checkPageBreak(y, 10);
      doc.text(line, x, y);
      y += fontSize * 0.45;
    }
    return y;
  }

  // Helper: section subheading
  function subheading(text: string, y: number): number {
    y = checkPageBreak(y, 20);
    doc.setTextColor(15, 23, 42);
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.text(text, margin, y);
    y += 6;
    return y;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // 1. COVER PAGE
  // ═══════════════════════════════════════════════════════════════════════
  doc.setFillColor(15, 23, 42);
  doc.rect(0, 0, pageWidth, pageHeight, 'F');

  // Title block
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(28);
  doc.setFont('helvetica', 'bold');
  doc.text('External Attack Surface', margin, 55);
  doc.text('Management Report', margin, 67);

  doc.setFontSize(16);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(148, 163, 184);
  doc.text(domain, margin, 82);

  // Risk score box
  let y = 100;
  doc.setFillColor(30, 41, 59);
  doc.roundedRect(margin, y, contentWidth, 50, 3, 3, 'F');

  doc.setTextColor(148, 163, 184);
  doc.setFontSize(9);
  doc.text('OVERALL RISK ASSESSMENT', margin + 5, y + 8);

  // Risk gauge
  const riskScore = scan.overallRiskScore ?? 0;
  const riskBand = scan.overallRiskBand || 'unknown';
  const riskColor = getRiskColor(riskBand);
  doc.setFillColor(riskColor[0], riskColor[1], riskColor[2]);
  doc.roundedRect(margin + 5, y + 12, 35, 30, 3, 3, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(22);
  doc.setFont('helvetica', 'bold');
  doc.text(String(riskScore), margin + 12, y + 28);
  doc.setFontSize(8);
  doc.text(riskBand.toUpperCase(), margin + 10, y + 37);

  // Key metrics
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(10);
  doc.setFont('helvetica', 'normal');
  const metricsX = margin + 50;
  doc.text(`Total Assets Discovered: ${scan.totalAssets ?? assets.length ?? 0}`, metricsX, y + 18);
  doc.text(`Total Findings: ${scan.totalFindings ?? 0}`, metricsX, y + 25);
  doc.text(`Data Sources Queried: ${scan.connectorResults?.length ?? 0}`, metricsX, y + 32);
  doc.text(`Scan Duration: ${scan.durationMs ? `${(scan.durationMs / 1000).toFixed(1)}s` : 'N/A'}`, metricsX, y + 39);

  // Classification & metadata
  y = 165;
  doc.setTextColor(148, 163, 184);
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.text(`Scan Date: ${scan.createdAt ? new Date(scan.createdAt).toLocaleString() : new Date().toLocaleString()}`, margin, y);
  doc.text(`Scan Mode: ${scan.scanMode || 'standard'}`, margin, y + 7);
  if (scan.orgProfile?.sector) {
    doc.text(`Sector: ${scan.orgProfile.sector}`, margin, y + 14);
  }
  if (scan.orgProfile?.clientType) {
    doc.text(`Client Type: ${scan.orgProfile.clientType}`, margin, y + 21);
  }

  // Footer
  doc.setFontSize(7);
  doc.setTextColor(100, 116, 139);
  doc.text('CONFIDENTIAL — For authorized recipients only', margin, pageHeight - 15);
  doc.text('AC3 Platform — Domain Intelligence Module', margin, pageHeight - 10);

  // ═══════════════════════════════════════════════════════════════════════
  // 2. EXECUTIVE SUMMARY
  // ═══════════════════════════════════════════════════════════════════════
  y = addSectionPage('Executive Summary');

  // Executive summary narrative
  if (scan.executiveSummary) {
    doc.setTextColor(51, 65, 85);
    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    y = writeText(scan.executiveSummary, margin, y, contentWidth);
    y += 6;
  }

  // Threat model summary
  if (scan.threatModelSummary) {
    y = subheading('Threat Model Assessment', y);
    doc.setTextColor(51, 65, 85);
    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    y = writeText(scan.threatModelSummary, margin, y, contentWidth);
    y += 6;
  }

  // LLM post-enrichment analysis
  if (llmAnalysis.executiveBrief) {
    y = subheading('AI-Enhanced Analysis', y);
    doc.setTextColor(51, 65, 85);
    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    y = writeText(llmAnalysis.executiveBrief, margin, y, contentWidth);
    y += 6;
  }

  // Key risk findings summary table
  const criticalAssets = assets.filter((a: any) => a.riskBand === 'critical' || a.hybridRiskScore >= 80);
  const highAssets = assets.filter((a: any) => a.riskBand === 'high' || (a.hybridRiskScore >= 60 && a.hybridRiskScore < 80));

  if (criticalAssets.length > 0 || highAssets.length > 0) {
    y = subheading('Critical & High Risk Assets', y);

    autoTable!(doc, {
      startY: y,
      head: [['Asset', 'Risk Score', 'Risk Band', 'Mission Function', 'Key Findings']],
      body: [...criticalAssets, ...highAssets].slice(0, 20).map((a: any) => [
        truncate(a.hostname || a.name, 40),
        String(a.hybridRiskScore ?? 0),
        (a.riskBand || 'unknown').toUpperCase(),
        truncate(a.missionFunction, 25),
        String(Array.isArray(a.postureFindings) ? a.postureFindings.length : 0),
      ]),
      theme: 'grid',
      headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 7, cellPadding: 1.5, textColor: [51, 65, 85] },
      alternateRowStyles: { fillColor: [241, 245, 249] },
      margin: { left: margin, right: margin },
      didParseCell: (data: any) => {
        if (data.section === 'body' && data.column.index === 2) {
          const text = String(data.cell.text).toUpperCase();
          if (text === 'CRITICAL') data.cell.styles.textColor = [220, 38, 38];
          else if (text === 'HIGH') data.cell.styles.textColor = [234, 88, 12];
        }
      },
    });
    y = (doc as any).lastAutoTable.finalY + 8;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // 3. ATTACK SURFACE INVENTORY
  // ═══════════════════════════════════════════════════════════════════════
  y = addSectionPage('Attack Surface Inventory');

  // Asset type breakdown
  const assetTypeCounts: Record<string, number> = {};
  const riskBandCounts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const asset of assets) {
    const aType = asset.assetType || 'unknown';
    assetTypeCounts[aType] = (assetTypeCounts[aType] || 0) + 1;
    const band = (asset.riskBand || 'low').toLowerCase();
    if (band in riskBandCounts) riskBandCounts[band]++;
  }

  y = subheading('Asset Distribution', y);

  // Asset type table
  autoTable!(doc, {
    startY: y,
    head: [['Asset Type', 'Count', '% of Total']],
    body: Object.entries(assetTypeCounts)
      .sort(([, a], [, b]) => b - a)
      .map(([type, count]) => [
        type.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
        String(count),
        `${assets.length > 0 ? ((count / assets.length) * 100).toFixed(1) : 0}%`,
      ]),
    theme: 'grid',
    headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
    bodyStyles: { fontSize: 7, cellPadding: 1.5, textColor: [51, 65, 85] },
    alternateRowStyles: { fillColor: [241, 245, 249] },
    margin: { left: margin, right: margin },
  });
  y = (doc as any).lastAutoTable.finalY + 8;

  // Risk distribution table
  y = subheading('Risk Distribution', y);

  autoTable!(doc, {
    startY: y,
    head: [['Risk Band', 'Count', '% of Total']],
    body: Object.entries(riskBandCounts)
      .filter(([, count]) => count > 0)
      .sort(([a], [b]) => {
        const order: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
        return (order[a] ?? 4) - (order[b] ?? 4);
      })
      .map(([band, count]) => [
        band.toUpperCase(),
        String(count),
        `${assets.length > 0 ? ((count / assets.length) * 100).toFixed(1) : 0}%`,
      ]),
    theme: 'grid',
    headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
    bodyStyles: { fontSize: 7, cellPadding: 1.5, textColor: [51, 65, 85] },
    alternateRowStyles: { fillColor: [241, 245, 249] },
    margin: { left: margin, right: margin },
    didParseCell: (data: any) => {
      if (data.section === 'body' && data.column.index === 0) {
        const text = String(data.cell.text).toUpperCase();
        if (text === 'CRITICAL') data.cell.styles.textColor = [220, 38, 38];
        else if (text === 'HIGH') data.cell.styles.textColor = [234, 88, 12];
        else if (text === 'MEDIUM') data.cell.styles.textColor = [202, 138, 4];
        else if (text === 'LOW') data.cell.styles.textColor = [22, 163, 74];
      }
    },
  });
  y = (doc as any).lastAutoTable.finalY + 8;

  // Full asset inventory table
  if (assets.length > 0) {
    y = subheading('Discovered Assets', y);

    autoTable!(doc, {
      startY: y,
      head: [['Hostname', 'Type', 'Risk', 'Band', 'Mission Function', 'Technologies']],
      body: assets.slice(0, 50).map((a: any) => [
        truncate(a.hostname || a.name, 35),
        (a.assetType || 'unknown').replace(/_/g, ' '),
        String(a.hybridRiskScore ?? 0),
        (a.riskBand || 'N/A').toUpperCase(),
        truncate(a.missionFunction, 20),
        truncate(Array.isArray(a.technologies) ? a.technologies.join(', ') : '', 30),
      ]),
      theme: 'grid',
      headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 6.5, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 6.5, cellPadding: 1.5, textColor: [51, 65, 85] },
      alternateRowStyles: { fillColor: [241, 245, 249] },
      margin: { left: margin, right: margin },
      didParseCell: (data: any) => {
        if (data.section === 'body' && data.column.index === 3) {
          const text = String(data.cell.text).toUpperCase();
          if (text === 'CRITICAL') data.cell.styles.textColor = [220, 38, 38];
          else if (text === 'HIGH') data.cell.styles.textColor = [234, 88, 12];
          else if (text === 'MEDIUM') data.cell.styles.textColor = [202, 138, 4];
        }
      },
      didDrawPage: () => addFooter(doc, margin, pageWidth, pageHeight),
    });
    y = (doc as any).lastAutoTable.finalY + 8;

    if (assets.length > 50) {
      doc.setTextColor(113, 113, 122);
      doc.setFontSize(7);
      doc.text(`Showing top 50 of ${assets.length} assets. Full inventory available in CSV export.`, margin, y);
      y += 6;
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // 4. DOMAIN HEALTH & BLACKLIST STATUS
  // ═══════════════════════════════════════════════════════════════════════
  y = addSectionPage('Domain Health & Blacklist Status');

  // DNS configuration
  if (domainHealth.dns) {
    y = subheading('DNS Configuration', y);
    const dns = domainHealth.dns;
    const dnsRows: string[][] = [];
    if (dns.aRecords?.length) dnsRows.push(['A Records', dns.aRecords.join(', ')]);
    if (dns.aaaaRecords?.length) dnsRows.push(['AAAA Records', dns.aaaaRecords.join(', ')]);
    if (dns.mxRecords?.length) dnsRows.push(['MX Records', dns.mxRecords.map((r: any) => `${r.exchange} (pri: ${r.priority})`).join(', ')]);
    if (dns.nsRecords?.length) dnsRows.push(['NS Records', dns.nsRecords.join(', ')]);
    if (dns.txtRecords?.length) dnsRows.push(['TXT Records', truncate(dns.txtRecords.join('; '), 100)]);

    if (dnsRows.length > 0) {
      autoTable!(doc, {
        startY: y,
        head: [['Record Type', 'Values']],
        body: dnsRows,
        theme: 'grid',
        headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
        bodyStyles: { fontSize: 7, cellPadding: 1.5, textColor: [51, 65, 85] },
        margin: { left: margin, right: margin },
        columnStyles: { 0: { cellWidth: 30 }, 1: { cellWidth: contentWidth - 30 } },
      });
      y = (doc as any).lastAutoTable.finalY + 8;
    }
  }

  // Email security
  if (domainHealth.emailSecurity) {
    y = subheading('Email Security Posture', y);
    const email = domainHealth.emailSecurity;
    const emailRows: string[][] = [];
    emailRows.push(['SPF', email.spf?.present ? `Present — ${truncate(email.spf.record, 60)}` : 'MISSING']);
    emailRows.push(['DKIM', email.dkim?.present ? 'Present' : 'NOT DETECTED']);
    emailRows.push(['DMARC', email.dmarc?.present ? `Present — Policy: ${email.dmarc.policy || 'none'}` : 'MISSING']);

    autoTable!(doc, {
      startY: y,
      head: [['Control', 'Status']],
      body: emailRows,
      theme: 'grid',
      headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 7, cellPadding: 1.5, textColor: [51, 65, 85] },
      margin: { left: margin, right: margin },
      didParseCell: (data: any) => {
        if (data.section === 'body' && data.column.index === 1) {
          const text = String(data.cell.text);
          if (text.startsWith('MISSING') || text.startsWith('NOT DETECTED')) {
            data.cell.styles.textColor = [220, 38, 38];
            data.cell.styles.fontStyle = 'bold';
          }
        }
      },
    });
    y = (doc as any).lastAutoTable.finalY + 8;
  }

  // SSL/TLS
  if (domainHealth.ssl) {
    y = subheading('SSL/TLS Certificate', y);
    const ssl = domainHealth.ssl;
    const sslRows: string[][] = [];
    sslRows.push(['Subject', ssl.subject || 'N/A']);
    sslRows.push(['Issuer', ssl.issuer || 'N/A']);
    sslRows.push(['Valid From', ssl.validFrom || 'N/A']);
    sslRows.push(['Valid To', ssl.validTo || 'N/A']);
    sslRows.push(['Days Until Expiry', String(ssl.daysUntilExpiry ?? 'N/A')]);
    sslRows.push(['Protocol', ssl.protocol || 'N/A']);
    if (ssl.sans?.length) sslRows.push(['SANs', truncate(ssl.sans.join(', '), 80)]);

    autoTable!(doc, {
      startY: y,
      head: [['Property', 'Value']],
      body: sslRows,
      theme: 'grid',
      headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 7, cellPadding: 1.5, textColor: [51, 65, 85] },
      margin: { left: margin, right: margin },
      columnStyles: { 0: { cellWidth: 35 } },
      didParseCell: (data: any) => {
        if (data.section === 'body' && data.row.index === 4) {
          const days = parseInt(String(data.cell.text));
          if (!isNaN(days) && days < 30) {
            data.cell.styles.textColor = [220, 38, 38];
            data.cell.styles.fontStyle = 'bold';
          }
        }
      },
    });
    y = (doc as any).lastAutoTable.finalY + 8;
  }

  // Blacklist / DNSBL status
  if (domainHealth.blacklist) {
    y = subheading('Blacklist / DNSBL Status', y);
    const bl = domainHealth.blacklist;

    if (bl.listings && bl.listings.length > 0) {
      // Warning box
      doc.setFillColor(254, 242, 242);
      doc.roundedRect(margin, y, contentWidth, 12, 2, 2, 'F');
      doc.setTextColor(220, 38, 38);
      doc.setFontSize(9);
      doc.setFont('helvetica', 'bold');
      doc.text(`LISTED ON ${bl.listings.length} BLACKLIST(S)`, margin + 5, y + 7);
      y += 16;

      autoTable!(doc, {
        startY: y,
        head: [['Zone', 'Category', 'Severity', 'Reason', 'False Positive?']],
        body: bl.listings.slice(0, 20).map((l: any) => [
          l.zone || 'N/A',
          (l.category || 'unknown').replace(/_/g, ' '),
          (l.severity || 'unknown').toUpperCase(),
          truncate(l.reason || l.txtReason || 'No reason provided', 50),
          l.isFalsePositive ? `Yes — ${truncate(l.falsePositiveReason, 30)}` : 'No',
        ]),
        theme: 'grid',
        headStyles: { fillColor: [127, 29, 29], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
        bodyStyles: { fontSize: 6.5, cellPadding: 1.5, textColor: [51, 65, 85] },
        alternateRowStyles: { fillColor: [254, 242, 242] },
        margin: { left: margin, right: margin },
        didParseCell: (data: any) => {
          if (data.section === 'body' && data.column.index === 2) {
            const text = String(data.cell.text).toUpperCase();
            if (text === 'CRITICAL') data.cell.styles.textColor = [220, 38, 38];
            else if (text === 'HIGH') data.cell.styles.textColor = [234, 88, 12];
          }
        },
      });
      y = (doc as any).lastAutoTable.finalY + 8;
    } else {
      doc.setFillColor(240, 253, 244);
      doc.roundedRect(margin, y, contentWidth, 12, 2, 2, 'F');
      doc.setTextColor(22, 163, 74);
      doc.setFontSize(9);
      doc.setFont('helvetica', 'bold');
      doc.text('NOT LISTED ON ANY MONITORED BLACKLISTS', margin + 5, y + 7);
      y += 16;
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // 5. BREACH & CREDENTIAL EXPOSURE
  // ═══════════════════════════════════════════════════════════════════════
  y = addSectionPage('Breach & Credential Exposure');

  // Filter credential observations
  const credentialObs = observations.filter((o: any) =>
    o.assetType === 'credential' ||
    o.tags?.includes('leaked_credential') ||
    o.tags?.includes('credential_breach')
  );

  // Dehashed breach database summaries
  const breachDbObs = observations.filter((o: any) =>
    o.tags?.includes('breach_database') && o.source === 'dehashed'
  );

  // Dehashed overall breach summary
  const breachSummaryObs = observations.find((o: any) =>
    o.tags?.includes('breach_summary') && o.source === 'dehashed'
  );

  const firstPartyObs = credentialObs.filter((o: any) =>
    o.evidence?.credential_source === 'first_party' || o.tags?.includes('first_party_breach')
  );
  const thirdPartyObs = credentialObs.filter((o: any) =>
    o.evidence?.credential_source === 'third_party' || o.tags?.includes('third_party_breach')
  );
  const unknownSourceObs = credentialObs.filter((o: any) =>
    !o.tags?.includes('first_party_breach') && !o.tags?.includes('third_party_breach')
  );

  // Breach overview box
  doc.setFillColor(30, 41, 59);
  doc.roundedRect(margin, y, contentWidth, 30, 3, 3, 'F');
  doc.setTextColor(148, 163, 184);
  doc.setFontSize(9);
  doc.text('CREDENTIAL EXPOSURE SUMMARY', margin + 5, y + 8);

  doc.setTextColor(255, 255, 255);
  doc.setFontSize(10);
  doc.setFont('helvetica', 'bold');
  doc.text(`Total Leaked Credentials: ${credentialObs.length}`, margin + 5, y + 17);
  doc.setFontSize(8);
  doc.setFont('helvetica', 'normal');

  if (firstPartyObs.length > 0) {
    doc.setTextColor(220, 38, 38);
    doc.text(`1st-Party Breaches: ${firstPartyObs.length}`, margin + 5, y + 24);
  } else {
    doc.setTextColor(34, 197, 94);
    doc.text('No 1st-Party Breaches Detected', margin + 5, y + 24);
  }
  doc.setTextColor(202, 138, 4);
  doc.text(`3rd-Party Credential Reuse: ${thirdPartyObs.length}`, margin + 80, y + 24);
  doc.setTextColor(148, 163, 184);
  doc.text(`Unclassified: ${unknownSourceObs.length}`, margin + 145, y + 24);
  y += 38;

  // Dehashed breach summary statistics
  if (breachSummaryObs) {
    const bsEvidence = breachSummaryObs.evidence || {};
    y = subheading('Breach Intelligence Summary (Dehashed)', y);

    doc.setFillColor(241, 245, 249);
    doc.roundedRect(margin, y, contentWidth, 22, 2, 2, 'F');
    doc.setTextColor(51, 65, 85);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    const col1X = margin + 5;
    const col2X = margin + 55;
    const col3X = margin + 110;
    doc.text(`Total Records: ${bsEvidence.total_records || 0}`, col1X, y + 7);
    doc.text(`Unique Breaches: ${bsEvidence.unique_breaches || 0}`, col2X, y + 7);
    doc.text(`Leaked Accounts: ${bsEvidence.unique_leaked_accounts || 0}`, col3X, y + 7);
    doc.text(`Subdomains Found: ${bsEvidence.unique_subdomains_found || 0}`, col1X, y + 14);
    doc.text(`Unique IPs: ${bsEvidence.unique_ips_found || 0}`, col2X, y + 14);
    doc.text(`Credentials Exposed: ${bsEvidence.credentials_exposed || 0}`, col3X, y + 14);
    y += 28;
  }

  // Dehashed breach database breakdown
  if (breachDbObs.length > 0) {
    y = subheading('Breach Database Attribution', y);

    doc.setTextColor(113, 113, 122);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'italic');
    doc.text('Individual breach databases where organization credentials were found.', margin, y);
    y += 6;

    autoTable!(doc, {
      startY: y,
      head: [['Breach Database', 'Records Found', 'Credentials Exposed', 'Has Passwords', 'Has Hashes']],
      body: breachDbObs
        .sort((a: any, b: any) => (b.evidence?.total_records || 0) - (a.evidence?.total_records || 0))
        .slice(0, 30)
        .map((o: any) => [
          o.evidence?.database_name || 'Unknown',
          String(o.evidence?.total_records || 0),
          String(o.evidence?.credentials_exposed || 0),
          o.evidence?.has_passwords ? 'YES' : 'No',
          o.evidence?.has_hashed_passwords ? 'YES' : 'No',
        ]),
      theme: 'grid',
      headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 6.5, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 6.5, cellPadding: 1.5, textColor: [51, 65, 85] },
      alternateRowStyles: { fillColor: [241, 245, 249] },
      margin: { left: margin, right: margin },
      didParseCell: (data: any) => {
        if (data.section === 'body' && (data.column.index === 3 || data.column.index === 4)) {
          const text = String(data.cell.text);
          if (text === 'YES') {
            data.cell.styles.textColor = [220, 38, 38];
            data.cell.styles.fontStyle = 'bold';
          }
        }
      },
    });
    y = (doc as any).lastAutoTable.finalY + 8;
  }

  // 1st-party breaches (critical — these are breaches of the target's own systems)
  if (firstPartyObs.length > 0) {
    y = subheading('1st-Party Breaches (Target Infrastructure Compromised)', y);

    doc.setTextColor(220, 38, 38);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'italic');
    doc.text('These credentials were leaked from breaches of the target organization\'s own systems.', margin, y);
    y += 6;

    autoTable!(doc, {
      startY: y,
      head: [['Email', 'Credential Type', 'Breach Source', 'Confidence', 'Reasoning']],
      body: firstPartyObs.slice(0, 30).map((o: any) => [
        truncate(o.evidence?.email || o.name, 30),
        (o.evidence?.credential_type || 'unknown').replace(/_/g, ' '),
        truncate(o.evidence?.database_name || o.evidence?.breach_name || 'N/A', 25),
        `${o.evidence?.credential_source_confidence || 0}%`,
        truncate(o.evidence?.credential_source_reasoning, 40),
      ]),
      theme: 'grid',
      headStyles: { fillColor: [127, 29, 29], textColor: [255, 255, 255], fontSize: 6.5, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 6.5, cellPadding: 1.5, textColor: [51, 65, 85] },
      alternateRowStyles: { fillColor: [254, 242, 242] },
      margin: { left: margin, right: margin },
      didParseCell: (data: any) => {
        if (data.section === 'body' && data.column.index === 1) {
          const text = String(data.cell.text).toLowerCase();
          if (text.includes('plaintext')) {
            data.cell.styles.textColor = [220, 38, 38];
            data.cell.styles.fontStyle = 'bold';
          }
        }
      },
    });
    y = (doc as any).lastAutoTable.finalY + 8;
  }

  // 3rd-party credential reuse
  if (thirdPartyObs.length > 0) {
    y = subheading('3rd-Party Credential Reuse', y);

    doc.setTextColor(113, 113, 122);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'italic');
    doc.text('Employees used their corporate email on external services that were subsequently breached.', margin, y);
    y += 6;

    autoTable!(doc, {
      startY: y,
      head: [['Email', 'Credential Type', 'External Service', 'Confidence']],
      body: thirdPartyObs.slice(0, 25).map((o: any) => [
        truncate(o.evidence?.email || o.name, 30),
        (o.evidence?.credential_type || 'unknown').replace(/_/g, ' '),
        truncate(o.evidence?.database_name || o.evidence?.breach_name || 'N/A', 30),
        `${o.evidence?.credential_source_confidence || 0}%`,
      ]),
      theme: 'grid',
      headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 6.5, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 6.5, cellPadding: 1.5, textColor: [51, 65, 85] },
      alternateRowStyles: { fillColor: [241, 245, 249] },
      margin: { left: margin, right: margin },
    });
    y = (doc as any).lastAutoTable.finalY + 8;

    if (thirdPartyObs.length > 25) {
      doc.setTextColor(113, 113, 122);
      doc.setFontSize(7);
      doc.text(`Showing 25 of ${thirdPartyObs.length} third-party credential exposures.`, margin, y);
      y += 6;
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // 6. DARK WEB & RANSOMWARE INTELLIGENCE
  // ═══════════════════════════════════════════════════════════════════════
  y = addSectionPage('Dark Web & Ransomware Intelligence');

  const darkwebObs = observations.filter((o: any) =>
    o.tags?.includes('darkweb') ||
    o.tags?.includes('ransomware_listing') ||
    o.tags?.includes('ransomware_live') ||
    o.tags?.includes('ransomware_victim') ||
    o.tags?.includes('iab_listing') ||
    o.tags?.includes('data_leak') ||
    o.tags?.includes('stealer_log') ||
    o.tags?.includes('underground_intel')
  );

  const ransomwareObs = darkwebObs.filter((o: any) =>
    o.tags?.includes('ransomware_listing') ||
    o.tags?.includes('ransomware_live') ||
    o.tags?.includes('ransomware_victim')
  );
  const iabObs = darkwebObs.filter((o: any) => o.tags?.includes('iab_listing') || o.tags?.includes('access_sale'));
  const dataLeakObs = darkwebObs.filter((o: any) => o.tags?.includes('data_leak'));
  const stealerObs = darkwebObs.filter((o: any) => o.tags?.includes('stealer_log') || o.tags?.includes('compromised_employee'));
  const threatGroupObs = darkwebObs.filter((o: any) => o.tags?.includes('threat_group'));

  // Summary box
  const hasDarkwebHits = darkwebObs.length > 0;
  if (hasDarkwebHits) {
    doc.setFillColor(50, 20, 20);
    doc.roundedRect(margin, y, contentWidth, 25, 3, 3, 'F');
    doc.setTextColor(220, 38, 38);
    doc.setFontSize(10);
    doc.setFont('helvetica', 'bold');
    doc.text(`${darkwebObs.length} DARK WEB MENTIONS DETECTED`, margin + 5, y + 10);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(255, 200, 200);
    const parts = [];
    if (ransomwareObs.length > 0) parts.push(`${ransomwareObs.length} ransomware`);
    if (iabObs.length > 0) parts.push(`${iabObs.length} IAB`);
    if (dataLeakObs.length > 0) parts.push(`${dataLeakObs.length} data leak`);
    if (stealerObs.length > 0) parts.push(`${stealerObs.length} stealer log`);
    if (threatGroupObs.length > 0) parts.push(`${threatGroupObs.length} threat group`);
    doc.text(parts.join(' | '), margin + 5, y + 18);
  } else {
    doc.setFillColor(240, 253, 244);
    doc.roundedRect(margin, y, contentWidth, 15, 3, 3, 'F');
    doc.setTextColor(22, 163, 74);
    doc.setFontSize(10);
    doc.setFont('helvetica', 'bold');
    doc.text('NO DARK WEB MENTIONS DETECTED', margin + 5, y + 10);
  }
  y += hasDarkwebHits ? 32 : 22;

  // Ransomware listings
  if (ransomwareObs.length > 0) {
    y = subheading('Ransomware Leak Site Listings', y);

    autoTable!(doc, {
      startY: y,
      head: [['Listing', 'Threat Actor / Group', 'Victim', 'Date', 'Match Type', 'Source']],
      body: ransomwareObs.slice(0, 20).map((o: any) => [
        truncate(o.evidence?.title || o.name, 35),
        o.evidence?.actor_name || o.evidence?.group_name || 'Unknown',
        truncate(o.evidence?.victim_name || o.evidence?.victim, 20),
        o.evidence?.event_date || o.evidence?.discovered || 'N/A',
        (o.evidence?.match_type || (o.tags?.includes('fuzzy_match') ? 'fuzzy' : 'exact')).replace(/_/g, ' '),
        o.source === 'ransomware_live' ? 'Ransomware.live' : 'DarkWeb CrossRef',
      ]),
      theme: 'grid',
      headStyles: { fillColor: [127, 29, 29], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 7, cellPadding: 1.5, textColor: [51, 65, 85] },
      alternateRowStyles: { fillColor: [254, 242, 242] },
      margin: { left: margin, right: margin },
    });
    y = (doc as any).lastAutoTable.finalY + 8;
  }

  // IAB listings
  if (iabObs.length > 0) {
    y = subheading('Initial Access Broker (IAB) Listings', y);

    autoTable!(doc, {
      startY: y,
      head: [['Listing', 'Actor', 'Date', 'Source']],
      body: iabObs.slice(0, 10).map((o: any) => [
        truncate(o.evidence?.title || o.name, 50),
        o.evidence?.actor_name || 'Unknown',
        o.evidence?.event_date || 'N/A',
        o.evidence?.source_feed || 'N/A',
      ]),
      theme: 'grid',
      headStyles: { fillColor: [127, 29, 29], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 7, cellPadding: 1.5, textColor: [51, 65, 85] },
      alternateRowStyles: { fillColor: [254, 242, 242] },
      margin: { left: margin, right: margin },
    });
    y = (doc as any).lastAutoTable.finalY + 8;
  }

  // Stealer log / compromised employee data
  if (stealerObs.length > 0) {
    y = subheading('Stealer Log & Compromised Employee Data', y);

    autoTable!(doc, {
      startY: y,
      head: [['Source', 'Details', 'Severity', 'Date']],
      body: stealerObs.slice(0, 15).map((o: any) => [
        o.source || 'N/A',
        truncate(o.name || o.evidence?.title, 50),
        getSeverityLabel(o.evidence?.severity || 5),
        o.firstSeen ? new Date(o.firstSeen).toLocaleDateString() : 'N/A',
      ]),
      theme: 'grid',
      headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 7, cellPadding: 1.5, textColor: [51, 65, 85] },
      alternateRowStyles: { fillColor: [241, 245, 249] },
      margin: { left: margin, right: margin },
    });
    y = (doc as any).lastAutoTable.finalY + 8;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // 7. THREAT ACTOR ASSESSMENT
  // ═══════════════════════════════════════════════════════════════════════
  if (threatGroupObs.length > 0) {
    y = addSectionPage('Threat Actor Assessment');

    for (const tg of threatGroupObs.slice(0, 5)) {
      y = checkPageBreak(y, 60);

      // Actor profile card
      doc.setFillColor(30, 41, 59);
      const cardHeight = 45;
      doc.roundedRect(margin, y, contentWidth, cardHeight, 3, 3, 'F');

      doc.setTextColor(255, 255, 255);
      doc.setFontSize(11);
      doc.setFont('helvetica', 'bold');
      doc.text(tg.evidence?.actor_name || 'Unknown Actor', margin + 5, y + 8);

      doc.setFontSize(8);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(148, 163, 184);
      const profileParts = [];
      if (tg.evidence?.actor_type) profileParts.push(`Type: ${tg.evidence.actor_type}`);
      if (tg.evidence?.origin) profileParts.push(`Origin: ${tg.evidence.origin}`);
      if (tg.evidence?.threat_level) profileParts.push(`Threat Level: ${tg.evidence.threat_level.toUpperCase()}`);
      if (tg.evidence?.sophistication) profileParts.push(`Sophistication: ${tg.evidence.sophistication}`);
      doc.text(profileParts.join(' | '), margin + 5, y + 14);

      if (tg.evidence?.motivation) {
        doc.text(`Motivation: ${tg.evidence.motivation}`, margin + 5, y + 20);
      }

      if (tg.evidence?.description) {
        doc.setTextColor(200, 210, 220);
        doc.setFontSize(7);
        const descLines = doc.splitTextToSize(truncate(tg.evidence.description, 300), contentWidth - 10);
        doc.text(descLines, margin + 5, y + 26);
      }

      // TTPs
      doc.setTextColor(148, 163, 184);
      doc.setFontSize(7);
      if (tg.evidence?.techniques) {
        const techniques = Array.isArray(tg.evidence.techniques) ? tg.evidence.techniques : [];
        if (techniques.length > 0) {
          doc.text(`TTPs: ${truncate(techniques.join(', '), 100)}`, margin + 5, y + 36);
        }
      }
      if (tg.evidence?.tools) {
        const tools = Array.isArray(tg.evidence.tools) ? tg.evidence.tools : [];
        if (tools.length > 0) {
          doc.text(`Tools: ${truncate(tools.join(', '), 100)}`, margin + 5, y + 40);
        }
      }

      y += cardHeight + 5;

      // Attributed events table
      if (tg.evidence?.attributed_events?.length > 0) {
        y = checkPageBreak(y, 30);
        doc.setTextColor(51, 65, 85);
        doc.setFontSize(8);
        doc.setFont('helvetica', 'bold');
        doc.text(`Attributed Incidents (${tg.evidence.attributed_events_count} total)`, margin, y);
        y += 4;

        autoTable!(doc, {
          startY: y,
          head: [['Type', 'Title', 'Victim', 'Sector', 'Date']],
          body: tg.evidence.attributed_events.slice(0, 10).map((e: any) => [
            (e.type || 'unknown').replace(/_/g, ' '),
            truncate(e.title, 40),
            truncate(e.victim, 20),
            truncate(e.sector, 15),
            e.date || 'N/A',
          ]),
          theme: 'grid',
          headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 6.5, fontStyle: 'bold', cellPadding: 2 },
          bodyStyles: { fontSize: 6.5, cellPadding: 1.5, textColor: [51, 65, 85] },
          alternateRowStyles: { fillColor: [241, 245, 249] },
          margin: { left: margin, right: margin },
        });
        y = (doc as any).lastAutoTable.finalY + 8;
      }

      // Relevant IOCs
      if (tg.evidence?.relevant_iocs?.length > 0) {
        y = checkPageBreak(y, 30);
        doc.setTextColor(51, 65, 85);
        doc.setFontSize(8);
        doc.setFont('helvetica', 'bold');
        doc.text(`Indicators of Compromise (${tg.evidence.relevant_iocs_count} total)`, margin, y);
        y += 4;

        autoTable!(doc, {
          startY: y,
          head: [['Type', 'Value', 'Confidence', 'First Seen', 'Last Seen']],
          body: tg.evidence.relevant_iocs.slice(0, 10).map((i: any) => [
            (i.type || 'unknown').replace(/_/g, ' '),
            truncate(i.value, 50),
            i.confidence || 'N/A',
            i.first_seen || 'N/A',
            i.last_seen || 'N/A',
          ]),
          theme: 'grid',
          headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 6.5, fontStyle: 'bold', cellPadding: 2 },
          bodyStyles: { fontSize: 6.5, cellPadding: 1.5, textColor: [51, 65, 85] },
          alternateRowStyles: { fillColor: [241, 245, 249] },
          margin: { left: margin, right: margin },
        });
        y = (doc as any).lastAutoTable.finalY + 10;
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // 8. VULNERABILITY & TECHNOLOGY LANDSCAPE
  // ═══════════════════════════════════════════════════════════════════════
  y = addSectionPage('Vulnerability & Technology Landscape');

  // Technology stack
  const allTechs = new Map<string, number>();
  for (const asset of assets) {
    if (Array.isArray(asset.technologies)) {
      for (const tech of asset.technologies) {
        allTechs.set(tech, (allTechs.get(tech) || 0) + 1);
      }
    }
  }

  if (allTechs.size > 0) {
    y = subheading('Technology Stack', y);

    autoTable!(doc, {
      startY: y,
      head: [['Technology', 'Assets Using', '% Coverage']],
      body: Array.from(allTechs.entries())
        .sort(([, a], [, b]) => b - a)
        .slice(0, 25)
        .map(([tech, count]) => [
          tech,
          String(count),
          `${assets.length > 0 ? ((count / assets.length) * 100).toFixed(1) : 0}%`,
        ]),
      theme: 'grid',
      headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 7, cellPadding: 1.5, textColor: [51, 65, 85] },
      alternateRowStyles: { fillColor: [241, 245, 249] },
      margin: { left: margin, right: margin },
    });
    y = (doc as any).lastAutoTable.finalY + 8;
  }

  // WAF/NGFW detection
  if (wafNgfw.detections?.length > 0) {
    y = subheading('WAF / NGFW Detection', y);

    autoTable!(doc, {
      startY: y,
      head: [['Asset', 'WAF/NGFW', 'Vendor', 'Confidence']],
      body: wafNgfw.detections.slice(0, 15).map((d: any) => [
        truncate(d.hostname || d.asset, 35),
        d.product || 'Unknown',
        d.vendor || 'Unknown',
        `${d.confidence || 0}%`,
      ]),
      theme: 'grid',
      headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 7, cellPadding: 1.5, textColor: [51, 65, 85] },
      alternateRowStyles: { fillColor: [241, 245, 249] },
      margin: { left: margin, right: margin },
    });
    y = (doc as any).lastAutoTable.finalY + 8;
  }

  // Vulnerability observations
  const vulnObs = observations.filter((o: any) =>
    o.tags?.includes('vulnerability') || o.tags?.includes('cve') || o.evidence?.cve_id
  );

  if (vulnObs.length > 0) {
    y = subheading('Identified Vulnerabilities', y);

    autoTable!(doc, {
      startY: y,
      head: [['CVE / Finding', 'Asset', 'Severity', 'Source', 'Description']],
      body: vulnObs.slice(0, 30).map((o: any) => [
        o.evidence?.cve_id || truncate(o.name, 25),
        truncate(o.evidence?.hostname || o.domain, 25),
        getSeverityLabel(o.evidence?.severity || 5),
        o.source || 'N/A',
        truncate(o.evidence?.description || o.evidence?.title, 40),
      ]),
      theme: 'grid',
      headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 6.5, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 6.5, cellPadding: 1.5, textColor: [51, 65, 85] },
      alternateRowStyles: { fillColor: [241, 245, 249] },
      margin: { left: margin, right: margin },
      didParseCell: (data: any) => {
        if (data.section === 'body' && data.column.index === 2) {
          const text = String(data.cell.text);
          if (text === 'Critical') data.cell.styles.textColor = [220, 38, 38];
          else if (text === 'High') data.cell.styles.textColor = [234, 88, 12];
        }
      },
    });
    y = (doc as any).lastAutoTable.finalY + 8;
  }

  // ═══════════════════════════════════════════════════════════════════════
  // 9. PRIORITIZED RECOMMENDATIONS
  // ═══════════════════════════════════════════════════════════════════════
  y = addSectionPage('Prioritized Recommendations');

  // LLM-generated recommendations
  if (llmAnalysis.recommendations?.length > 0) {
    autoTable!(doc, {
      startY: y,
      head: [['Priority', 'Recommendation', 'Category', 'Effort']],
      body: llmAnalysis.recommendations.slice(0, 20).map((r: any, i: number) => [
        `P${i + 1}`,
        truncate(r.recommendation || r.title || r, 60),
        truncate(r.category || 'General', 20),
        r.effort || 'N/A',
      ]),
      theme: 'grid',
      headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 7, cellPadding: 1.5, textColor: [51, 65, 85] },
      alternateRowStyles: { fillColor: [241, 245, 249] },
      margin: { left: margin, right: margin },
      didParseCell: (data: any) => {
        if (data.section === 'body' && data.column.index === 0) {
          const text = String(data.cell.text);
          if (text === 'P1') data.cell.styles.textColor = [220, 38, 38];
          else if (text === 'P2') data.cell.styles.textColor = [234, 88, 12];
          else if (text === 'P3') data.cell.styles.textColor = [202, 138, 4];
        }
      },
    });
    y = (doc as any).lastAutoTable.finalY + 8;
  }

  // Attack chains / blind spots from LLM analysis
  if (llmAnalysis.attackChains?.length > 0) {
    y = subheading('Identified Attack Chains', y);

    for (const chain of llmAnalysis.attackChains.slice(0, 5)) {
      y = checkPageBreak(y, 20);
      doc.setTextColor(51, 65, 85);
      doc.setFontSize(8);
      doc.setFont('helvetica', 'bold');
      doc.text(`Chain: ${truncate(chain.name || chain.title, 60)}`, margin, y);
      y += 4;
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7);
      y = writeText(truncate(chain.description || chain.narrative, 300), margin + 3, y, contentWidth - 6, 7);
      y += 4;
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // 10. APPENDIX — DATA SOURCES & METHODOLOGY
  // ═══════════════════════════════════════════════════════════════════════
  y = addSectionPage('Appendix: Data Sources & Methodology');

  // Connector results
  if (scan.connectorResults?.length > 0) {
    y = subheading('Data Sources Queried', y);

    autoTable!(doc, {
      startY: y,
      head: [['Source', 'Observations', 'Duration', 'Status']],
      body: scan.connectorResults
        .sort((a: any, b: any) => (b.observations?.length || 0) - (a.observations?.length || 0))
        .slice(0, 40)
        .map((cr: any) => [
          (cr.connector || 'unknown').replace(/_/g, ' '),
          String(cr.observations?.length || 0),
          cr.durationMs ? `${(cr.durationMs / 1000).toFixed(1)}s` : 'N/A',
          cr.errors?.length > 0 ? `Error: ${truncate(cr.errors[0], 30)}` : cr.rateLimited ? 'Rate Limited' : 'OK',
        ]),
      theme: 'grid',
      headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 6.5, cellPadding: 1.5, textColor: [51, 65, 85] },
      alternateRowStyles: { fillColor: [241, 245, 249] },
      margin: { left: margin, right: margin },
      didParseCell: (data: any) => {
        if (data.section === 'body' && data.column.index === 3) {
          const text = String(data.cell.text);
          if (text.startsWith('Error')) data.cell.styles.textColor = [220, 38, 38];
          else if (text === 'Rate Limited') data.cell.styles.textColor = [234, 88, 12];
          else if (text === 'OK') data.cell.styles.textColor = [22, 163, 74];
        }
      },
    });
    y = (doc as any).lastAutoTable.finalY + 8;
  }

  // Discovery coverage
  if (discoveryCoverage.coveragePercentage !== undefined) {
    y = subheading('Discovery Coverage', y);
    doc.setTextColor(51, 65, 85);
    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    doc.text(`Overall Coverage: ${discoveryCoverage.coveragePercentage}%`, margin, y);
    y += 5;
    if (discoveryCoverage.gaps?.length > 0) {
      doc.text(`Identified Gaps: ${discoveryCoverage.gaps.join(', ')}`, margin, y);
      y += 5;
    }
  }

  // Scan metadata
  y = checkPageBreak(y, 30);
  y = subheading('Scan Metadata', y);
  const metaRows: string[][] = [
    ['Scan ID', String(scan.id || 'N/A')],
    ['Domain', domain],
    ['Scan Mode', scan.scanMode || 'standard'],
    ['Started', scan.createdAt ? new Date(scan.createdAt).toLocaleString() : 'N/A'],
    ['Duration', scan.durationMs ? `${(scan.durationMs / 1000).toFixed(1)} seconds` : 'N/A'],
    ['Total Observations', String(observations.length)],
    ['Total Assets', String(assets.length)],
    ['Report Generated', new Date().toLocaleString()],
  ];

  autoTable!(doc, {
    startY: y,
    head: [['Property', 'Value']],
    body: metaRows,
    theme: 'grid',
    headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
    bodyStyles: { fontSize: 7, cellPadding: 1.5, textColor: [51, 65, 85] },
    margin: { left: margin, right: margin },
    columnStyles: { 0: { cellWidth: 40 } },
  });

  // ═══════════════════════════════════════════════════════════════════════
  // FOOTER ON ALL PAGES
  // ═══════════════════════════════════════════════════════════════════════
  const pageCount = (doc as any).internal.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(7);
    doc.setTextColor(148, 163, 184);
    doc.text(`Page ${i} of ${pageCount}`, pageWidth - 30, pageHeight - 8);
    doc.text('CONFIDENTIAL — For authorized recipients only', margin, pageHeight - 8);
  }

  doc.save(`EASM_Report_${domain}_${dateStamp()}.pdf`);
}

// Helper: add footer to current page
function addFooter(doc: any, margin: number, pageWidth: number, pageHeight: number) {
  doc.setFontSize(7);
  doc.setTextColor(148, 163, 184);
  doc.text(`Page ${doc.getCurrentPageInfo().pageNumber}`, pageWidth - 30, pageHeight - 8);
  doc.text('CONFIDENTIAL', margin, pageHeight - 8);
}
