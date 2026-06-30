/**
 * Universal Data Export Utility
 * 
 * Provides CSV and PDF export for scan results, findings, scoring data,
 * and engagement deliverables. Operators can export data for client reports.
 */
// Dynamic imports to reduce bundle size — jspdf is 29MB and only needed for PDF export
let _jsPDF: typeof import('jspdf').default | null = null;
let _autoTable: typeof import('jspdf-autotable').default | null = null;
async function loadPdfLibs() {
  if (!_jsPDF) _jsPDF = (await import('jspdf')).default;
  if (!_autoTable) _autoTable = (await import('jspdf-autotable')).default;
  return { jsPDF: _jsPDF, autoTable: _autoTable };
}

// ─── CSV Export ─────────────────────────────────────────────────────────

interface CsvColumn<T> {
  header: string;
  accessor: (row: T) => string | number | boolean | null | undefined;
}

export function exportToCsv<T>(
  filename: string,
  columns: CsvColumn<T>[],
  data: T[],
): void {
  const headers = columns.map(c => c.header);
  const rows = data.map(row =>
    columns.map(col => {
      const val = col.accessor(row);
      if (val === null || val === undefined) return '';
      const str = String(val);
      // Escape CSV: wrap in quotes if contains comma, newline, or quote
      if (str.includes(',') || str.includes('\n') || str.includes('"')) {
        return `"${str.replace(/"/g, '""')}"`;
      }
      return str;
    })
  );

  const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
  const blob = new Blob(['\ufeff' + csvContent], { type: 'text/csv;charset=utf-8;' });
  downloadBlob(blob, filename.endsWith('.csv') ? filename : `${filename}.csv`);
}

// ─── PDF Export ─────────────────────────────────────────────────────────

interface PdfExportOptions {
  title: string;
  subtitle?: string;
  filename: string;
  orientation?: 'portrait' | 'landscape';
  metadata?: Array<{ label: string; value: string }>;
}

interface PdfTableSection {
  heading?: string;
  columns: string[];
  rows: (string | number)[][];
}

export async function exportToPdf(
  options: PdfExportOptions,
  sections: PdfTableSection[],
): Promise<void> {
  const { jsPDF, autoTable } = await loadPdfLibs();
  const doc = new jsPDF({
    orientation: options.orientation || 'landscape',
    unit: 'mm',
    format: 'a4',
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  let yPos = 15;

  // Header bar
  doc.setFillColor(24, 24, 27); // zinc-900
  doc.rect(0, 0, pageWidth, 28, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(16);
  doc.setFont('helvetica', 'bold');
  doc.text(options.title, 14, 12);
  if (options.subtitle) {
    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    doc.text(options.subtitle, 14, 19);
  }
  doc.setFontSize(8);
  doc.setTextColor(161, 161, 170); // zinc-400
  doc.text(`Generated: ${new Date().toLocaleString()}`, 14, 25);
  doc.text('AC3 Platform', pageWidth - 40, 25);

  yPos = 34;

  // Metadata section
  if (options.metadata && options.metadata.length > 0) {
    doc.setTextColor(63, 63, 70); // zinc-700
    doc.setFontSize(8);
    const metaPerRow = 4;
    const colWidth = (pageWidth - 28) / metaPerRow;
    options.metadata.forEach((m, i) => {
      const col = i % metaPerRow;
      const row = Math.floor(i / metaPerRow);
      const x = 14 + col * colWidth;
      const y = yPos + row * 8;
      doc.setFont('helvetica', 'bold');
      doc.text(`${m.label}:`, x, y);
      doc.setFont('helvetica', 'normal');
      doc.text(` ${m.value}`, x + doc.getTextWidth(`${m.label}: `), y);
    });
    yPos += Math.ceil(options.metadata.length / metaPerRow) * 8 + 4;
  }

  // Table sections
  for (const section of sections) {
    if (section.heading) {
      doc.setTextColor(24, 24, 27);
      doc.setFontSize(11);
      doc.setFont('helvetica', 'bold');
      doc.text(section.heading, 14, yPos);
      yPos += 6;
    }

    autoTable!(doc, {
      startY: yPos,
      head: [section.columns],
      body: section.rows.map(row => row.map(cell => String(cell ?? ''))),
      theme: 'grid',
      headStyles: {
        fillColor: [39, 39, 42], // zinc-800
        textColor: [255, 255, 255],
        fontSize: 7,
        fontStyle: 'bold',
        cellPadding: 2,
      },
      bodyStyles: {
        fontSize: 7,
        cellPadding: 1.5,
        textColor: [39, 39, 42],
      },
      alternateRowStyles: {
        fillColor: [244, 244, 245], // zinc-100
      },
      margin: { left: 14, right: 14 },
      didDrawPage: () => {
        // Footer on every page
        const pageCount = (doc as any).internal.getNumberOfPages();
        doc.setFontSize(7);
        doc.setTextColor(161, 161, 170);
        doc.text(
          `Page ${doc.getCurrentPageInfo().pageNumber} of ${pageCount}`,
          pageWidth - 30,
          doc.internal.pageSize.getHeight() - 8,
        );
        doc.text(
          'CONFIDENTIAL — For authorized recipients only',
          14,
          doc.internal.pageSize.getHeight() - 8,
        );
      },
    });

    yPos = (doc as any).lastAutoTable.finalY + 8;
  }

  doc.save(options.filename.endsWith('.pdf') ? options.filename : `${options.filename}.pdf`);
}

// ─── Pre-built Export Functions ─────────────────────────────────────────

/** Export discovered assets from a scan */
export function exportScanAssets(
  domain: string,
  assets: any[],
  format: 'csv' | 'pdf' = 'csv',
): void {
  const filename = `${domain}_assets_${dateStamp()}`;

  if (format === 'csv') {
    exportToCsv(filename, [
      { header: 'Hostname', accessor: (a: any) => a.hostname },
      { header: 'Asset Type', accessor: (a: any) => a.assetType },
      { header: 'Risk Score', accessor: (a: any) => a.hybridRiskScore },
      { header: 'Risk Band', accessor: (a: any) => a.riskBand },
      { header: 'Impact Score', accessor: (a: any) => a.impactScore },
      { header: 'Likelihood Score', accessor: (a: any) => a.likelihoodScore },
      { header: 'Criticality Score', accessor: (a: any) => a.assetCriticalityScore },
      { header: 'Criticality Band', accessor: (a: any) => a.assetCriticalityBand },
      { header: 'Vuln Risk Score', accessor: (a: any) => a.vulnRiskScore },
      { header: 'Vuln Risk Band', accessor: (a: any) => a.vulnRiskBand },
      { header: 'Mission Function', accessor: (a: any) => a.missionFunction },
      { header: 'Essential Service', accessor: (a: any) => a.essentialService },
      { header: 'Business Impact', accessor: (a: any) => a.businessImpactLevel },
      { header: 'Suggested Tier', accessor: (a: any) => a.suggestedTier },
      { header: 'Findings Count', accessor: (a: any) => Array.isArray(a.postureFindings) ? a.postureFindings.length : 0 },
      { header: 'Technologies', accessor: (a: any) => Array.isArray(a.technologies) ? a.technologies.join('; ') : '' },
    ], assets);
  } else {
    exportToPdf(
      {
        title: `Asset Inventory — ${domain}`,
        subtitle: `${assets.length} discovered assets`,
        filename,
        orientation: 'landscape',
        metadata: [
          { label: 'Domain', value: domain },
          { label: 'Total Assets', value: String(assets.length) },
          { label: 'Critical', value: String(assets.filter((a: any) => a.riskBand === 'critical').length) },
          { label: 'High', value: String(assets.filter((a: any) => a.riskBand === 'high').length) },
        ],
      },
      [{
        heading: 'Discovered Assets',
        columns: ['Hostname', 'Type', 'Risk', 'Band', 'Impact', 'Likelihood', 'Mission Function', 'Tier'],
        rows: assets.map((a: any) => [
          a.hostname,
          a.assetType || 'unknown',
          a.hybridRiskScore ?? 0,
          (a.riskBand || 'low').toUpperCase(),
          a.impactScore ?? 0,
          a.likelihoodScore ?? 0,
          a.missionFunction || 'N/A',
          a.suggestedTier || 'N/A',
        ]),
      }],
    );
  }
}

/** Export posture findings from a scan */
export function exportFindings(
  domain: string,
  findings: any[],
  format: 'csv' | 'pdf' = 'csv',
): void {
  const filename = `${domain}_findings_${dateStamp()}`;

  if (format === 'csv') {
    exportToCsv(filename, [
      { header: 'Asset', accessor: (f: any) => f.assetHostname || f.assetRef },
      { header: 'Category', accessor: (f: any) => f.category },
      { header: 'Title', accessor: (f: any) => f.title },
      { header: 'Severity', accessor: (f: any) => f.severity },
      { header: 'Likelihood', accessor: (f: any) => f.likelihood },
      { header: 'Confidence', accessor: (f: any) => typeof f.confidence === 'number' ? (f.confidence * 100).toFixed(0) + '%' : '' },
      { header: 'Corroboration', accessor: (f: any) => f.corroborationTier },
      { header: 'CVE IDs', accessor: (f: any) => Array.isArray(f.cveIds) ? f.cveIds.join('; ') : '' },
      { header: 'KEV Listed', accessor: (f: any) => f.kevListed ? 'Yes' : 'No' },
      { header: 'Exploit Available', accessor: (f: any) => f.exploitAvailable ? 'Yes' : 'No' },
      { header: 'CVSS', accessor: (f: any) => f.cvssScore },
      { header: 'Evidence Basis', accessor: (f: any) => f.evidenceBasis },
      { header: 'Recommended Controls', accessor: (f: any) => Array.isArray(f.recommendedControls) ? f.recommendedControls.join('; ') : '' },
    ], findings);
  } else {
    const critFindings = findings.filter((f: any) => f.severity >= 8);
    const highFindings = findings.filter((f: any) => f.severity >= 6 && f.severity < 8);
    const medFindings = findings.filter((f: any) => f.severity >= 4 && f.severity < 6);
    const lowFindings = findings.filter((f: any) => f.severity < 4);

    const sections: PdfTableSection[] = [];
    const cols = ['Asset', 'Category', 'Title', 'Sev', 'Corroboration', 'CVEs', 'KEV'];
    const toRow = (f: any) => [
      f.assetHostname || f.assetRef || '',
      f.category || '',
      (f.title || '').substring(0, 80),
      f.severity ?? 0,
      f.corroborationTier || '',
      Array.isArray(f.cveIds) ? f.cveIds.join(', ') : '',
      f.kevListed ? 'YES' : '',
    ];

    if (critFindings.length > 0) sections.push({ heading: `Critical Findings (${critFindings.length})`, columns: cols, rows: critFindings.map(toRow) });
    if (highFindings.length > 0) sections.push({ heading: `High Findings (${highFindings.length})`, columns: cols, rows: highFindings.map(toRow) });
    if (medFindings.length > 0) sections.push({ heading: `Medium Findings (${medFindings.length})`, columns: cols, rows: medFindings.map(toRow) });
    if (lowFindings.length > 0) sections.push({ heading: `Low Findings (${lowFindings.length})`, columns: cols, rows: lowFindings.map(toRow) });

    exportToPdf(
      {
        title: `Security Findings Report — ${domain}`,
        subtitle: `${findings.length} findings across ${new Set(findings.map((f: any) => f.assetHostname || f.assetRef)).size} assets`,
        filename,
        orientation: 'landscape',
        metadata: [
          { label: 'Domain', value: domain },
          { label: 'Total Findings', value: String(findings.length) },
          { label: 'Critical', value: String(critFindings.length) },
          { label: 'High', value: String(highFindings.length) },
          { label: 'Medium', value: String(medFindings.length) },
          { label: 'Low', value: String(lowFindings.length) },
          { label: 'KEV Matches', value: String(findings.filter((f: any) => f.kevListed).length) },
          { label: 'Exploitable', value: String(findings.filter((f: any) => f.exploitAvailable).length) },
        ],
      },
      sections,
    );
  }
}

/** Export scoring audit timeline */
export function exportScoringTimeline(
  domain: string,
  timeline: any[],
  format: 'csv' | 'pdf' = 'csv',
): void {
  const filename = `${domain}_scoring_timeline_${dateStamp()}`;

  if (format === 'csv') {
    exportToCsv(filename, [
      { header: 'Asset ID', accessor: (e: any) => e.assetId },
      { header: 'Timestamp', accessor: (e: any) => e.computedAt ? new Date(e.computedAt).toISOString() : '' },
      { header: 'Trigger', accessor: (e: any) => e.triggerType || 'manual' },
      { header: 'Phase', accessor: (e: any) => e.pipelinePhase || '' },
      { header: 'Previous Score', accessor: (e: any) => e.previousScore },
      { header: 'New Score', accessor: (e: any) => e.hybridRiskScore },
      { header: 'Delta', accessor: (e: any) => e.delta },
      { header: 'Risk Band', accessor: (e: any) => e.riskBand },
      { header: 'Impact', accessor: (e: any) => e.impactScore },
      { header: 'Likelihood', accessor: (e: any) => e.likelihoodScore },
      { header: 'Description', accessor: (e: any) => e.changeDescription || '' },
    ], timeline);
  } else {
    exportToPdf(
      {
        title: `Scoring Timeline — ${domain}`,
        subtitle: `${timeline.length} scoring events`,
        filename,
        orientation: 'landscape',
      },
      [{
        heading: 'Scoring Events',
        columns: ['Time', 'Trigger', 'Phase', 'Prev', 'New', 'Delta', 'Band', 'Description'],
        rows: timeline.map((e: any) => [
          e.computedAt ? new Date(e.computedAt).toLocaleString() : '',
          e.triggerType || 'manual',
          e.pipelinePhase || '',
          e.previousScore ?? '',
          e.hybridRiskScore ?? '',
          e.delta ?? '',
          (e.riskBand || '').toUpperCase(),
          (e.changeDescription || '').substring(0, 60),
        ]),
      }],
    );
  }
}

/** Export threat actor matches */
export function exportThreatActors(
  domain: string,
  actors: any[],
  format: 'csv' | 'pdf' = 'csv',
): void {
  const filename = `${domain}_threat_actors_${dateStamp()}`;

  if (format === 'csv') {
    exportToCsv(filename, [
      { header: 'Name', accessor: (a: any) => a.name },
      { header: 'Aliases', accessor: (a: any) => Array.isArray(a.aliases) ? a.aliases.join('; ') : '' },
      { header: 'Confidence', accessor: (a: any) => a.confidence },
      { header: 'Sophistication', accessor: (a: any) => a.sophistication },
      { header: 'Target Sectors', accessor: (a: any) => Array.isArray(a.targetSectors) ? a.targetSectors.join('; ') : '' },
      { header: 'TTPs', accessor: (a: any) => Array.isArray(a.ttps) ? a.ttps.join('; ') : '' },
      { header: 'Rationale', accessor: (a: any) => a.rationale },
    ], actors);
  } else {
    exportToPdf(
      {
        title: `Threat Actor Assessment — ${domain}`,
        subtitle: `${actors.length} matched threat actors`,
        filename,
        metadata: [
          { label: 'Domain', value: domain },
          { label: 'Actors Matched', value: String(actors.length) },
        ],
      },
      [{
        heading: 'Threat Actor Matches',
        columns: ['Name', 'Confidence', 'Sophistication', 'Target Sectors', 'Rationale'],
        rows: actors.map((a: any) => [
          a.name || '',
          a.confidence || '',
          a.sophistication || '',
          Array.isArray(a.targetSectors) ? a.targetSectors.join(', ') : '',
          (a.rationale || '').substring(0, 100),
        ]),
      }],
    );
  }
}

/** Export executive summary as PDF */
export async function exportExecutiveSummary(
  domain: string,
  scan: any,
): Promise<void> {
  const { jsPDF, autoTable } = await loadPdfLibs();
  const filename = `${domain}_executive_summary_${dateStamp()}`;
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
  const pageWidth = doc.internal.pageSize.getWidth();

  // Title page
  doc.setFillColor(24, 24, 27);
  doc.rect(0, 0, pageWidth, 60, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(22);
  doc.setFont('helvetica', 'bold');
  doc.text('Executive Summary', 20, 25);
  doc.setFontSize(14);
  doc.setFont('helvetica', 'normal');
  doc.text(domain, 20, 35);
  doc.setFontSize(9);
  doc.setTextColor(161, 161, 170);
  doc.text(`Generated: ${new Date().toLocaleString()} | AC3 Platform`, 20, 50);

  let y = 70;

  // Risk overview
  doc.setTextColor(24, 24, 27);
  doc.setFontSize(13);
  doc.setFont('helvetica', 'bold');
  doc.text('Risk Overview', 20, y);
  y += 8;

  const riskColor = getRiskColor(scan.overallRiskBand);
  doc.setFillColor(riskColor[0], riskColor[1], riskColor[2]);
  doc.roundedRect(20, y, 40, 20, 3, 3, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(18);
  doc.setFont('helvetica', 'bold');
  doc.text(String(scan.overallRiskScore ?? 0), 30, y + 13);
  doc.setFontSize(8);
  doc.text((scan.overallRiskBand || 'N/A').toUpperCase(), 30, y + 18);

  // Stats
  doc.setTextColor(63, 63, 70);
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.text(`Total Assets: ${scan.totalAssets ?? 0}`, 70, y + 6);
  doc.text(`Total Findings: ${scan.totalFindings ?? 0}`, 70, y + 12);
  doc.text(`Scan Date: ${scan.createdAt ? new Date(scan.createdAt).toLocaleDateString() : 'N/A'}`, 70, y + 18);
  y += 30;

  // Executive summary text
  if (scan.executiveSummary) {
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.text('Summary', 20, y);
    y += 6;
    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    const lines = doc.splitTextToSize(scan.executiveSummary, pageWidth - 40);
    doc.text(lines, 20, y);
    y += lines.length * 4 + 6;
  }

  // Threat model summary
  if (scan.threatModelSummary) {
    if (y > 240) { doc.addPage(); y = 20; }
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.text('Threat Model', 20, y);
    y += 6;
    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    const lines = doc.splitTextToSize(scan.threatModelSummary, pageWidth - 40);
    doc.text(lines, 20, y);
  }

  // Footer
  const pageCount = (doc as any).internal.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(7);
    doc.setTextColor(161, 161, 170);
    doc.text(
      `Page ${i} of ${pageCount} — CONFIDENTIAL`,
      14,
      doc.internal.pageSize.getHeight() - 8,
    );
  }

  doc.save(`${filename}.pdf`);
}

// ─── Helpers ────────────────────────────────────────────────────────────

function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function dateStamp(): string {
  return new Date().toISOString().slice(0, 10).replace(/-/g, '');
}

function getRiskColor(band: string): [number, number, number] {
  switch (band) {
    case 'critical': return [220, 38, 38];   // red-600
    case 'high': return [234, 88, 12];       // orange-600
    case 'medium': return [202, 138, 4];     // yellow-600
    case 'low': return [22, 163, 74];        // green-600
    default: return [113, 113, 122];         // zinc-500
  }
}

// ─── BIA Report PDF Export ──────────────────────────────────────────────

export async function exportBiaReportPdf(report: any): Promise<void> {
  const { jsPDF, autoTable } = await loadPdfLibs();
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4',
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 15;
  const contentWidth = pageWidth - margin * 2;
  let yPos = 0;

  // ─── Cover Page ─────────────────────────────────────────────────────
  doc.setFillColor(15, 23, 42); // slate-900
  doc.rect(0, 0, pageWidth, pageHeight, 'F');

  // Title block
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(28);
  doc.setFont('helvetica', 'bold');
  doc.text('Business Impact Analysis', margin, 60);
  doc.setFontSize(14);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(148, 163, 184); // slate-400
  doc.text(report.organization.customerName, margin, 72);
  doc.text(report.organization.primaryDomain, margin, 80);

  // FIPS 199 box
  yPos = 100;
  doc.setFillColor(30, 41, 59); // slate-800
  doc.roundedRect(margin, yPos, contentWidth, 35, 3, 3, 'F');
  doc.setTextColor(148, 163, 184);
  doc.setFontSize(9);
  doc.text('FIPS 199 SECURITY CATEGORIZATION', margin + 5, yPos + 8);
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');
  const catX = margin + 5;
  doc.text(`Confidentiality: ${report.systemSecurityCategorization.confidentiality}`, catX, yPos + 18);
  doc.text(`Integrity: ${report.systemSecurityCategorization.integrity}`, catX + 55, yPos + 18);
  doc.text(`Availability: ${report.systemSecurityCategorization.availability}`, catX + 105, yPos + 18);
  doc.setFontSize(12);
  doc.text(`Overall: ${report.systemSecurityCategorization.overall}`, catX, yPos + 28);

  // Risk score box
  yPos = 145;
  doc.setFillColor(30, 41, 59);
  doc.roundedRect(margin, yPos, contentWidth, 25, 3, 3, 'F');
  doc.setTextColor(148, 163, 184);
  doc.setFontSize(9);
  doc.text('OVERALL RISK ASSESSMENT', margin + 5, yPos + 8);
  doc.setFontSize(14);
  doc.setFont('helvetica', 'bold');
  const riskColor = getRiskColor(report.overallRiskBand);
  doc.setTextColor(riskColor[0], riskColor[1], riskColor[2]);
  doc.text(`${report.overallRiskScore}/100 (${report.overallRiskBand.toUpperCase()})`, margin + 5, yPos + 19);
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(10);
  doc.setFont('helvetica', 'normal');
  doc.text(`${report.assetCount} assets | ${report.criticalAssetCount} critical | ${report.highAssetCount} high`, margin + 80, yPos + 19);

  // Metadata
  yPos = 185;
  doc.setTextColor(148, 163, 184);
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.text(`Sector: ${report.organization.sector}`, margin, yPos);
  doc.text(`Client Type: ${report.organization.clientType}`, margin, yPos + 7);
  doc.text(`Generated: ${new Date(report.generatedAt).toLocaleString()}`, margin, yPos + 14);
  if (report.organization.complianceFlags?.length > 0) {
    doc.text(`Compliance: ${report.organization.complianceFlags.join(', ')}`, margin, yPos + 21);
  }

  // Footer
  doc.setFontSize(7);
  doc.setTextColor(100, 116, 139);
  doc.text('CONFIDENTIAL — For authorized recipients only', margin, pageHeight - 15);
  doc.text('NIST IR 8286D | FIPS 199 | NIST SP 800-34 Rev. 1', margin, pageHeight - 10);

  // ─── Content Pages ──────────────────────────────────────────────────
  for (const section of report.sections) {
    doc.addPage();
    yPos = margin;

    // Section header
    doc.setFillColor(15, 23, 42);
    doc.rect(0, 0, pageWidth, 20, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text(section.title, margin, 13);
    yPos = 28;

    // Section content - wrap text
    doc.setTextColor(51, 65, 85); // slate-700
    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');

    const cleanContent = section.content
      .replace(/\*\*(.*?)\*\*/g, '$1')
      .replace(/\n- /g, '\n• ');

    const lines = doc.splitTextToSize(cleanContent, contentWidth);
    for (const line of lines) {
      if (yPos > pageHeight - 25) {
        doc.addPage();
        yPos = margin;
      }
      doc.text(line, margin, yPos);
      yPos += 4.5;
    }

    // Tables
    if (section.tables) {
      for (const table of section.tables) {
        yPos += 4;
        if (yPos > pageHeight - 40) {
          doc.addPage();
          yPos = margin;
        }

        // Table caption
        doc.setTextColor(100, 116, 139);
        doc.setFontSize(8);
        doc.setFont('helvetica', 'bold');
        doc.text(table.caption, margin, yPos);
        yPos += 4;

        autoTable!(doc, {
          startY: yPos,
          head: [table.headers],
          body: table.rows.map((row: string[]) => row.map(cell => String(cell ?? ''))),
          theme: 'grid',
          headStyles: {
            fillColor: [30, 41, 59],
            textColor: [255, 255, 255],
            fontSize: 7,
            fontStyle: 'bold',
            cellPadding: 2,
          },
          bodyStyles: {
            fontSize: 6.5,
            cellPadding: 1.5,
            textColor: [51, 65, 85],
          },
          alternateRowStyles: {
            fillColor: [241, 245, 249], // slate-100
          },
          margin: { left: margin, right: margin },
          didParseCell: (data: any) => {
            const text = String(data.cell.text).toUpperCase();
            if (data.section === 'body') {
              if (text === 'CRITICAL') data.cell.styles.textColor = [220, 38, 38];
              else if (text === 'HIGH') data.cell.styles.textColor = [234, 88, 12];
              else if (text === 'MODERATE' || text === 'MEDIUM') data.cell.styles.textColor = [202, 138, 4];
              else if (text === 'YES') { data.cell.styles.textColor = [220, 38, 38]; data.cell.styles.fontStyle = 'bold'; }
            }
          },
          didDrawPage: () => {
            doc.setFontSize(7);
            doc.setTextColor(148, 163, 184);
            doc.text(
              `Page ${doc.getCurrentPageInfo().pageNumber}`,
              pageWidth - 25,
              pageHeight - 8,
            );
            doc.text('CONFIDENTIAL', margin, pageHeight - 8);
          },
        });

        yPos = (doc as any).lastAutoTable.finalY + 8;
      }
    }
  }

  doc.save(`BIA_Report_${report.organization.primaryDomain}_${dateStamp()}.pdf`);
}


// ─── Proof-of-Exploit Evidence Export ──────────────────────────────────────

export interface EvidenceArtifactExport {
  type: string;
  filename: string;
  url: string;
  mimeType: string;
  sizeBytes: number;
  capturedAt: string;
}

export interface ValidationResultExport {
  assetHostname: string;
  cveId: string;
  msfModule: string | null;
  status: string;
  exploitable: boolean;
  scoreAdjustment: number;
  durationMs: number;
  evidence: {
    checkOutput?: string;
    msfJobId?: string;
    auxiliaryScanner?: string;
    timestamp?: string;
  } | null;
  errorMessage: string | null;
  timestamp: string;
  /** Primary evidence report URL (S3) */
  evidenceUrl?: string | null;
  /** All captured evidence artifacts */
  evidenceArtifacts?: EvidenceArtifactExport[] | null;
}

export interface ValidationRunExport {
  id: number;
  scanId: number;
  mode: string;
  status: string;
  totalCandidates: number;
  validated: number;
  exploitable: number;
  notVulnerable: number;
  errors: number;
  startedAt: string;
  completedAt: string | null;
}

/** Export validation results as CSV */
export function exportValidationResultsCsv(
  domain: string,
  results: ValidationResultExport[],
): void {
  exportToCsv(`${domain}_validation_results_${dateStamp()}`, [
    { header: 'Asset', accessor: (r) => r.assetHostname },
    { header: 'CVE', accessor: (r) => r.cveId },
    { header: 'MSF Module', accessor: (r) => r.msfModule || '' },
    { header: 'Status', accessor: (r) => r.status },
    { header: 'Exploitable', accessor: (r) => r.exploitable ? 'YES' : 'NO' },
    { header: 'Score Adjustment', accessor: (r) => r.scoreAdjustment },
    { header: 'Duration (ms)', accessor: (r) => r.durationMs },
    { header: 'Evidence', accessor: (r) => r.evidence?.checkOutput?.substring(0, 200) || '' },
    { header: 'Error', accessor: (r) => r.errorMessage || '' },
    { header: 'Timestamp', accessor: (r) => r.timestamp },
  ], results);
}

/** Export validation results as PDF with proof-of-exploit evidence */
export async function exportValidationReportPdf(
  domain: string,
  run: ValidationRunExport,
  results: ValidationResultExport[],
): Promise<void> {
  const { jsPDF, autoTable } = await loadPdfLibs();
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 15;
  const contentWidth = pageWidth - margin * 2;

  // ─── Cover Page ─────────────────────────────────────────────────────
  doc.setFillColor(15, 23, 42);
  doc.rect(0, 0, pageWidth, pageHeight, 'F');

  doc.setTextColor(255, 255, 255);
  doc.setFontSize(26);
  doc.setFont('helvetica', 'bold');
  doc.text('Exploitation Validation Report', margin, 55);

  doc.setFontSize(13);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(148, 163, 184);
  doc.text(domain, margin, 67);
  doc.text(`Proof-of-Exploit Evidence — ${run.mode.replace('_', ' ').toUpperCase()} Mode`, margin, 77);

  // Summary box
  let y = 95;
  doc.setFillColor(30, 41, 59);
  doc.roundedRect(margin, y, contentWidth, 45, 3, 3, 'F');
  doc.setTextColor(148, 163, 184);
  doc.setFontSize(9);
  doc.text('VALIDATION SUMMARY', margin + 5, y + 8);

  doc.setTextColor(255, 255, 255);
  doc.setFontSize(11);
  doc.setFont('helvetica', 'bold');

  const exploitableColor: [number, number, number] = run.exploitable > 0 ? [220, 38, 38] : [34, 197, 94];
  doc.setTextColor(exploitableColor[0], exploitableColor[1], exploitableColor[2]);
  doc.text(`${run.exploitable} CONFIRMED EXPLOITABLE`, margin + 5, y + 19);

  doc.setTextColor(255, 255, 255);
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.text(`Total Candidates: ${run.totalCandidates}`, margin + 5, y + 28);
  doc.text(`Validated: ${run.validated}`, margin + 55, y + 28);
  doc.text(`Not Vulnerable: ${run.notVulnerable}`, margin + 95, y + 28);
  doc.text(`Errors: ${run.errors}`, margin + 145, y + 28);

  doc.text(`Started: ${run.startedAt ? new Date(run.startedAt).toLocaleString() : 'N/A'}`, margin + 5, y + 37);
  doc.text(`Completed: ${run.completedAt ? new Date(run.completedAt).toLocaleString() : 'In Progress'}`, margin + 80, y + 37);

  // Exploitable findings highlight
  const exploitableResults = results.filter(r => r.exploitable);
  if (exploitableResults.length > 0) {
    y = 155;
    doc.setFillColor(30, 20, 20);
    doc.roundedRect(margin, y, contentWidth, 8 + exploitableResults.length * 7, 3, 3, 'F');
    doc.setTextColor(220, 38, 38);
    doc.setFontSize(9);
    doc.setFont('helvetica', 'bold');
    doc.text('CONFIRMED EXPLOITABLE VULNERABILITIES', margin + 5, y + 7);
    doc.setTextColor(255, 200, 200);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    exploitableResults.forEach((r, i) => {
      doc.text(
        `${r.assetHostname} — ${r.cveId} — ${r.msfModule || 'N/A'} — Score +${r.scoreAdjustment}`,
        margin + 5,
        y + 14 + i * 7,
      );
    });
  }

  // Footer
  doc.setFontSize(7);
  doc.setTextColor(100, 116, 139);
  doc.text('CONFIDENTIAL — Proof-of-Exploit Evidence — For authorized recipients only', margin, pageHeight - 10);

  // ─── Detailed Results Table ─────────────────────────────────────────
  doc.addPage();

  doc.setFillColor(15, 23, 42);
  doc.rect(0, 0, pageWidth, 20, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(14);
  doc.setFont('helvetica', 'bold');
  doc.text('Detailed Validation Results', margin, 13);

  autoTable(doc, {
    startY: 28,
    head: [['Asset', 'CVE', 'MSF Module', 'Status', 'Exploitable', 'Score Adj.', 'Duration']],
    body: results.map(r => [
      r.assetHostname,
      r.cveId,
      (r.msfModule || 'N/A').substring(0, 35),
      r.status.toUpperCase(),
      r.exploitable ? 'YES' : 'NO',
      r.exploitable ? `+${r.scoreAdjustment}` : '0',
      `${(r.durationMs / 1000).toFixed(1)}s`,
    ]),
    theme: 'grid',
    headStyles: {
      fillColor: [30, 41, 59],
      textColor: [255, 255, 255],
      fontSize: 7,
      fontStyle: 'bold',
      cellPadding: 2,
    },
    bodyStyles: {
      fontSize: 7,
      cellPadding: 1.5,
      textColor: [51, 65, 85],
    },
    alternateRowStyles: {
      fillColor: [241, 245, 249],
    },
    margin: { left: margin, right: margin },
    didParseCell: (data: any) => {
      if (data.section === 'body') {
        const text = String(data.cell.text).toUpperCase();
        if (text === 'YES') { data.cell.styles.textColor = [220, 38, 38]; data.cell.styles.fontStyle = 'bold'; }
        else if (text === 'VALIDATED') data.cell.styles.textColor = [220, 38, 38];
        else if (text === 'NOT_VULNERABLE') data.cell.styles.textColor = [34, 197, 94];
        else if (text === 'SKIPPED') data.cell.styles.textColor = [113, 113, 122];
        else if (text === 'ERROR') data.cell.styles.textColor = [234, 88, 12];
      }
    },
    didDrawPage: () => {
      doc.setFontSize(7);
      doc.setTextColor(148, 163, 184);
      doc.text(`Page ${doc.getCurrentPageInfo().pageNumber}`, pageWidth - 25, pageHeight - 8);
      doc.text('CONFIDENTIAL — Proof-of-Exploit Evidence', margin, pageHeight - 8);
    },
  });

  // ─── Evidence Details Page ──────────────────────────────────────────
  const resultsWithEvidence = results.filter(r => r.evidence?.checkOutput || r.evidenceUrl || (r.evidenceArtifacts && r.evidenceArtifacts.length > 0));
  if (resultsWithEvidence.length > 0) {
    doc.addPage();

    doc.setFillColor(15, 23, 42);
    doc.rect(0, 0, pageWidth, 20, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text('Evidence Details', margin, 13);

    y = 28;
    for (const r of resultsWithEvidence) {
      if (y > pageHeight - 50) {
        doc.addPage();
        y = margin;
      }

      // Evidence card
      doc.setFillColor(241, 245, 249);
      const evidenceText = r.evidence?.checkOutput || '';
      const wrappedEvidence = evidenceText ? doc.splitTextToSize(evidenceText.substring(0, 500), contentWidth - 10) : [];
      const artifactCount = r.evidenceArtifacts?.length ?? 0;
      const artifactLines = artifactCount > 0 ? artifactCount + 1 : 0; // header + one line per artifact
      const cardHeight = 22 + wrappedEvidence.length * 3.5 + artifactLines * 4;
      doc.roundedRect(margin, y, contentWidth, cardHeight, 2, 2, 'F');

      doc.setTextColor(15, 23, 42);
      doc.setFontSize(9);
      doc.setFont('helvetica', 'bold');
      doc.text(`${r.assetHostname} — ${r.cveId}`, margin + 5, y + 6);

      doc.setTextColor(100, 116, 139);
      doc.setFontSize(7);
      doc.setFont('helvetica', 'normal');
      doc.text(`Module: ${r.msfModule || 'N/A'} | Status: ${r.status} | Exploitable: ${r.exploitable ? 'YES' : 'NO'}`, margin + 5, y + 12);

      let cardY = y + 18;

      // MSF output text
      if (wrappedEvidence.length > 0) {
        doc.setTextColor(51, 65, 85);
        doc.setFontSize(7);
        doc.text(wrappedEvidence, margin + 5, cardY);
        cardY += wrappedEvidence.length * 3.5 + 2;
      }

      // Evidence artifacts list with S3 URLs
      if (r.evidenceArtifacts && r.evidenceArtifacts.length > 0) {
        doc.setTextColor(30, 64, 175); // blue-800
        doc.setFontSize(7);
        doc.setFont('helvetica', 'bold');
        doc.text('Evidence Artifacts:', margin + 5, cardY);
        cardY += 4;
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(6.5);
        for (const artifact of r.evidenceArtifacts) {
          const artifactLabel = `${artifact.type}: ${artifact.filename}`;
          const sizeStr = artifact.sizeBytes < 1024 ? `${artifact.sizeBytes} B` : `${(artifact.sizeBytes / 1024).toFixed(1)} KB`;
          doc.setTextColor(30, 64, 175);
          doc.textWithLink(artifactLabel, margin + 8, cardY, { url: artifact.url });
          doc.setTextColor(100, 116, 139);
          doc.text(` (${sizeStr})`, margin + 8 + doc.getTextWidth(artifactLabel), cardY);
          cardY += 4;
        }
      } else if (r.evidenceUrl) {
        // Fallback: just show the primary evidence report link
        doc.setTextColor(30, 64, 175);
        doc.setFontSize(7);
        doc.setFont('helvetica', 'bold');
        doc.text('Evidence Report:', margin + 5, cardY);
        doc.setFont('helvetica', 'normal');
        doc.textWithLink('View Full Evidence Report', margin + 40, cardY, { url: r.evidenceUrl });
        cardY += 4;
      }

      y += cardHeight + 5;
    }
  }

  doc.save(`Validation_Report_${domain}_${dateStamp()}.pdf`);
}

/** Add validation evidence section to executive summary PDF */
export async function exportExecutiveSummaryWithValidation(
  domain: string,
  scan: any,
  validationRun: ValidationRunExport | null,
  validationResults: ValidationResultExport[],
): Promise<void> {
  const { jsPDF, autoTable } = await loadPdfLibs();
  const filename = `${domain}_executive_summary_${dateStamp()}`;
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 15;
  const contentWidth = pageWidth - margin * 2;

  // ─── Title Page (same as original) ──────────────────────────────────
  doc.setFillColor(24, 24, 27);
  doc.rect(0, 0, pageWidth, 60, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(22);
  doc.setFont('helvetica', 'bold');
  doc.text('Executive Summary', 20, 25);
  doc.setFontSize(14);
  doc.setFont('helvetica', 'normal');
  doc.text(domain, 20, 35);
  doc.setFontSize(9);
  doc.setTextColor(161, 161, 170);
  doc.text(`Generated: ${new Date().toLocaleString()} | AC3 Platform`, 20, 50);

  let y = 70;

  // Risk overview
  doc.setTextColor(24, 24, 27);
  doc.setFontSize(13);
  doc.setFont('helvetica', 'bold');
  doc.text('Risk Overview', 20, y);
  y += 8;

  const riskColor = getRiskColor(scan.overallRiskBand);
  doc.setFillColor(riskColor[0], riskColor[1], riskColor[2]);
  doc.roundedRect(20, y, 40, 20, 3, 3, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(18);
  doc.setFont('helvetica', 'bold');
  doc.text(String(scan.overallRiskScore ?? 0), 30, y + 13);
  doc.setFontSize(8);
  doc.text((scan.overallRiskBand || 'N/A').toUpperCase(), 30, y + 18);

  doc.setTextColor(63, 63, 70);
  doc.setFontSize(9);
  doc.setFont('helvetica', 'normal');
  doc.text(`Total Assets: ${scan.totalAssets ?? 0}`, 70, y + 6);
  doc.text(`Total Findings: ${scan.totalFindings ?? 0}`, 70, y + 12);
  doc.text(`Scan Date: ${scan.createdAt ? new Date(scan.createdAt).toLocaleDateString() : 'N/A'}`, 70, y + 18);
  y += 30;

  // ─── Validation Coverage Metric ──────────────────────────────────────
  if (validationRun && validationResults.length > 0) {
    const totalCritical = scan.totalFindings ?? validationResults.length;
    const validated = validationResults.filter((r: any) => r.status === 'validated' || r.status === 'not_vulnerable').length;
    const exploitable = validationResults.filter((r: any) => r.exploitable).length;
    const coveragePct = totalCritical > 0 ? Math.round((validated / totalCritical) * 100) : 0;
    const exploitablePct = validated > 0 ? Math.round((exploitable / validated) * 100) : 0;

    doc.setTextColor(24, 24, 27);
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.text('Validation Coverage', 20, y);
    y += 7;

    // Coverage bar background
    const barWidth = 80;
    const barHeight = 8;
    doc.setFillColor(228, 228, 231);
    doc.roundedRect(20, y, barWidth, barHeight, 2, 2, 'F');
    // Coverage bar fill
    const fillWidth = Math.max(2, (coveragePct / 100) * barWidth);
    const barColor = coveragePct >= 80 ? [34, 197, 94] : coveragePct >= 50 ? [234, 179, 8] : [239, 68, 68];
    doc.setFillColor(barColor[0], barColor[1], barColor[2]);
    doc.roundedRect(20, y, fillWidth, barHeight, 2, 2, 'F');
    // Coverage percentage text
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(7);
    doc.setFont('helvetica', 'bold');
    if (fillWidth > 15) doc.text(`${coveragePct}%`, 22, y + 5.5);

    // Coverage stats
    doc.setTextColor(63, 63, 70);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.text(`${validated} of ${totalCritical} critical findings validated`, 105, y + 3);
    doc.text(`${exploitable} confirmed exploitable (${exploitablePct}%)`, 105, y + 7.5);
    y += 14;

    // Quality assessment
    doc.setFontSize(8);
    doc.setFont('helvetica', 'italic');
    doc.setTextColor(113, 113, 122);
    const qualityMsg = coveragePct >= 80
      ? 'High validation coverage \u2014 findings are well-substantiated with proof-of-exploit evidence.'
      : coveragePct >= 50
      ? 'Moderate validation coverage \u2014 additional validation recommended for remaining critical findings.'
      : 'Low validation coverage \u2014 significant portion of critical findings remain unconfirmed.';
    doc.text(qualityMsg, 20, y);
    y += 8;
  }

  // Executive summary text
  if (scan.executiveSummary) {
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.text('Summary', 20, y);
    y += 6;
    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    const lines = doc.splitTextToSize(scan.executiveSummary, contentWidth);
    doc.text(lines, 20, y);
    y += lines.length * 4 + 6;
  }

  // ─── Validation Evidence Section ──────────────────────────────────────
  if (validationRun && validationResults.length > 0) {
    if (y > 200) { doc.addPage(); y = 20; }

    doc.setTextColor(24, 24, 27);
    doc.setFontSize(13);
    doc.setFont('helvetica', 'bold');
    doc.text('Exploitation Validation Evidence', 20, y);
    y += 8;

    // Validation summary stats
    const exploitable = validationResults.filter(r => r.exploitable);
    const notVuln = validationResults.filter(r => r.status === 'not_vulnerable');

    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(63, 63, 70);
    doc.text(`Validation Mode: ${validationRun.mode.replace('_', ' ')}`, 20, y);
    y += 5;

    // Exploitable count in red
    if (exploitable.length > 0) {
      doc.setTextColor(220, 38, 38);
      doc.setFont('helvetica', 'bold');
      doc.text(`${exploitable.length} vulnerabilities confirmed exploitable`, 20, y);
      y += 5;
    }

    doc.setTextColor(34, 197, 94);
    doc.setFont('helvetica', 'normal');
    doc.text(`${notVuln.length} findings verified not exploitable`, 20, y);
    y += 8;

    // Exploitable findings table
    if (exploitable.length > 0) {
      doc.setTextColor(24, 24, 27);
      doc.setFontSize(10);
      doc.setFont('helvetica', 'bold');
      doc.text('Confirmed Exploitable Findings', 20, y);
      y += 4;

      autoTable!(doc, {
        startY: y,
        head: [['Asset', 'CVE', 'MSF Module', 'Score Impact', 'Evidence', 'Artifacts']],
        body: exploitable.map(r => [
          r.assetHostname,
          r.cveId,
          (r.msfModule || 'N/A').substring(0, 30),
          `+${r.scoreAdjustment}`,
          (r.evidence?.checkOutput || 'Exploitation confirmed').substring(0, 50),
          r.evidenceArtifacts?.length ? `${r.evidenceArtifacts.length} files` : r.evidenceUrl ? 'Report' : 'N/A',
        ]),
        theme: 'grid',
        headStyles: {
          fillColor: [127, 29, 29], // red-900
          textColor: [255, 255, 255],
          fontSize: 7,
          fontStyle: 'bold',
          cellPadding: 2,
        },
        bodyStyles: {
          fontSize: 7,
          cellPadding: 1.5,
          textColor: [39, 39, 42],
        },
        alternateRowStyles: {
          fillColor: [254, 242, 242], // red-50
        },
        margin: { left: 20, right: 20 },
      });

      y = (doc as any).lastAutoTable.finalY + 8;
    }

    // Not vulnerable findings (brief)
    if (notVuln.length > 0 && y < 240) {
      doc.setTextColor(24, 24, 27);
      doc.setFontSize(10);
      doc.setFont('helvetica', 'bold');
      doc.text('Verified Not Exploitable', 20, y);
      y += 4;

      autoTable!(doc, {
        startY: y,
        head: [['Asset', 'CVE', 'MSF Module', 'Result']],
        body: notVuln.slice(0, 15).map(r => [
          r.assetHostname,
          r.cveId,
          (r.msfModule || 'N/A').substring(0, 30),
          'Not Vulnerable',
        ]),
        theme: 'grid',
        headStyles: {
          fillColor: [20, 83, 45], // green-900
          textColor: [255, 255, 255],
          fontSize: 7,
          fontStyle: 'bold',
          cellPadding: 2,
        },
        bodyStyles: {
          fontSize: 7,
          cellPadding: 1.5,
          textColor: [39, 39, 42],
        },
        alternateRowStyles: {
          fillColor: [240, 253, 244], // green-50
        },
        margin: { left: 20, right: 20 },
      });
    }
  }

  // Threat model summary
  if (scan.threatModelSummary) {
    y = (doc as any).lastAutoTable?.finalY + 10 || y + 6;
    if (y > 240) { doc.addPage(); y = 20; }
    doc.setTextColor(24, 24, 27);
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.text('Threat Model', 20, y);
    y += 6;
    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    const lines = doc.splitTextToSize(scan.threatModelSummary, contentWidth);
    doc.text(lines, 20, y);
  }

  // Footer on all pages
  const pageCount = (doc as any).internal.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(7);
    doc.setTextColor(161, 161, 170);
    doc.text(`Page ${i} of ${pageCount} — CONFIDENTIAL`, 14, pageHeight - 8);
  }

  doc.save(`${filename}.pdf`);
}
