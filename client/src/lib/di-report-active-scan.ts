/**
 * DI Report Active Scan & Web Crawl Data Integration
 * 
 * Pulls tool execution records from scan_results and web_crawl_results
 * to provide rich evidence in the DI report.
 * 
 * This module handles:
 *   - Formatting tool results for the "Tool Results" section
 *   - Extracting security header findings from web crawl data
 *   - Building evidence chains from multiple tool executions
 *   - Generating the "Active Verification" section content
 */

import type { jsPDF } from 'jspdf';

// ═══════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════

export interface ToolResult {
  id: number;
  tool: string;
  target: string;
  command?: string;
  rawOutput?: string;
  rawStderr?: string;
  exitCode?: number;
  durationMs?: number;
  timedOut?: boolean;
  findings?: any[];
  findingCount?: number;
  severitySummary?: { critical?: number; high?: number; medium?: number; low?: number; info?: number };
  phase?: string;
  createdAt?: string;
}

export interface WebCrawlResult {
  id: number;
  targetUrl: string;
  finalUrl?: string;
  domain: string;
  httpStatus?: number;
  responseTimeMs?: number;
  securityHeaders?: Record<string, string>;
  securityHeaderGrade?: string;
  detectedTechnologies?: string[];
  serverHeader?: string;
  poweredBy?: string;
  pageTitle?: string;
  forms?: any[];
  exposedPaths?: string[];
  cookies?: any[];
  tlsInfo?: any;
  findings?: any[];
  totalFindings?: number;
  rawHeaders?: Record<string, string>;
}

export interface ActiveScanSummary {
  totalToolRuns: number;
  totalFindings: number;
  toolBreakdown: { tool: string; runs: number; findings: number; avgDuration: number }[];
  severityDistribution: { critical: number; high: number; medium: number; low: number; info: number };
  topFindings: { tool: string; finding: string; severity: string; target: string; evidence?: string }[];
}

export interface WebCrawlSummary {
  totalPagesCrawled: number;
  averageResponseTime: number;
  securityGrades: { grade: string; count: number }[];
  missingHeaders: { header: string; count: number; percentage: number }[];
  detectedTechnologies: { tech: string; count: number }[];
  exposedForms: { url: string; action?: string; method?: string; hasFileUpload?: boolean }[];
  cookieIssues: { url: string; issue: string }[];
  tlsIssues: { url: string; issue: string }[];
}

// ═══════════════════════════════════════════════════════════════════════
// DATA PROCESSING
// ═══════════════════════════════════════════════════════════════════════

/**
 * Summarize active scan tool results for the report.
 */
export function summarizeToolResults(results: ToolResult[]): ActiveScanSummary {
  const toolMap = new Map<string, { runs: number; findings: number; totalDuration: number }>();
  let totalFindings = 0;
  const severity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const topFindings: ActiveScanSummary['topFindings'] = [];

  for (const r of results) {
    const entry = toolMap.get(r.tool) || { runs: 0, findings: 0, totalDuration: 0 };
    entry.runs++;
    entry.findings += r.findingCount || 0;
    entry.totalDuration += r.durationMs || 0;
    toolMap.set(r.tool, entry);

    totalFindings += r.findingCount || 0;

    // Aggregate severity
    if (r.severitySummary) {
      severity.critical += r.severitySummary.critical || 0;
      severity.high += r.severitySummary.high || 0;
      severity.medium += r.severitySummary.medium || 0;
      severity.low += r.severitySummary.low || 0;
      severity.info += r.severitySummary.info || 0;
    }

    // Extract top findings
    if (r.findings && Array.isArray(r.findings)) {
      for (const f of r.findings.slice(0, 3)) {
        topFindings.push({
          tool: r.tool,
          finding: f.name || f.templateId || f.title || 'Unknown',
          severity: f.severity || f.info?.severity || 'info',
          target: r.target,
          evidence: f.matchedAt || f.extractedResults?.[0] || f.curlCommand || undefined,
        });
      }
    }
  }

  // Sort top findings by severity
  const sevOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  topFindings.sort((a, b) => (sevOrder[b.severity] || 0) - (sevOrder[a.severity] || 0));

  return {
    totalToolRuns: results.length,
    totalFindings,
    toolBreakdown: Array.from(toolMap.entries()).map(([tool, data]) => ({
      tool,
      runs: data.runs,
      findings: data.findings,
      avgDuration: data.runs > 0 ? Math.round(data.totalDuration / data.runs) : 0,
    })).sort((a, b) => b.findings - a.findings),
    severityDistribution: severity,
    topFindings: topFindings.slice(0, 20),
  };
}

/**
 * Summarize web crawl results for the security headers section.
 */
export function summarizeWebCrawl(results: WebCrawlResult[]): WebCrawlSummary {
  const criticalHeaders = [
    'strict-transport-security',
    'content-security-policy',
    'x-frame-options',
    'x-content-type-options',
    'referrer-policy',
    'permissions-policy',
  ];

  const gradeMap = new Map<string, number>();
  const headerMissing = new Map<string, number>();
  const techMap = new Map<string, number>();
  const forms: WebCrawlSummary['exposedForms'] = [];
  const cookieIssues: WebCrawlSummary['cookieIssues'] = [];
  const tlsIssues: WebCrawlSummary['tlsIssues'] = [];
  let totalResponseTime = 0;
  let responseTimeCount = 0;

  for (const r of results) {
    // Security header grades
    if (r.securityHeaderGrade) {
      gradeMap.set(r.securityHeaderGrade, (gradeMap.get(r.securityHeaderGrade) || 0) + 1);
    }

    // Missing headers
    if (r.securityHeaders) {
      for (const h of criticalHeaders) {
        if (!r.securityHeaders[h] && !r.securityHeaders[h.toLowerCase()]) {
          headerMissing.set(h, (headerMissing.get(h) || 0) + 1);
        }
      }
    }

    // Technologies
    if (r.detectedTechnologies) {
      for (const tech of r.detectedTechnologies) {
        techMap.set(tech, (techMap.get(tech) || 0) + 1);
      }
    }

    // Forms
    if (r.forms && Array.isArray(r.forms)) {
      for (const form of r.forms) {
        forms.push({
          url: r.targetUrl || r.finalUrl || '',
          action: form.action,
          method: form.method,
          hasFileUpload: form.hasFileUpload || form.inputs?.some((i: any) => i.type === 'file'),
        });
      }
    }

    // Cookie issues
    if (r.cookies && Array.isArray(r.cookies)) {
      for (const cookie of r.cookies) {
        if (!cookie.secure) cookieIssues.push({ url: r.targetUrl || '', issue: `Cookie "${cookie.name}" missing Secure flag` });
        if (!cookie.httpOnly && cookie.name?.toLowerCase().includes('session')) {
          cookieIssues.push({ url: r.targetUrl || '', issue: `Session cookie "${cookie.name}" missing HttpOnly flag` });
        }
        if (cookie.sameSite === 'none' || !cookie.sameSite) {
          cookieIssues.push({ url: r.targetUrl || '', issue: `Cookie "${cookie.name}" has weak SameSite policy` });
        }
      }
    }

    // TLS issues
    if (r.tlsInfo) {
      const tls = r.tlsInfo;
      if (tls.protocol && (tls.protocol.includes('TLSv1.0') || tls.protocol.includes('TLSv1.1'))) {
        tlsIssues.push({ url: r.targetUrl || '', issue: `Deprecated TLS version: ${tls.protocol}` });
      }
      if (tls.cipher && tls.cipher.includes('RC4')) {
        tlsIssues.push({ url: r.targetUrl || '', issue: `Weak cipher: ${tls.cipher}` });
      }
    }

    // Response time
    if (r.responseTimeMs) {
      totalResponseTime += r.responseTimeMs;
      responseTimeCount++;
    }
  }

  return {
    totalPagesCrawled: results.length,
    averageResponseTime: responseTimeCount > 0 ? Math.round(totalResponseTime / responseTimeCount) : 0,
    securityGrades: Array.from(gradeMap.entries())
      .map(([grade, count]) => ({ grade, count }))
      .sort((a, b) => a.grade.localeCompare(b.grade)),
    missingHeaders: Array.from(headerMissing.entries())
      .map(([header, count]) => ({
        header,
        count,
        percentage: results.length > 0 ? Math.round((count / results.length) * 100) : 0,
      }))
      .sort((a, b) => b.percentage - a.percentage),
    detectedTechnologies: Array.from(techMap.entries())
      .map(([tech, count]) => ({ tech, count }))
      .sort((a, b) => b.count - a.count),
    exposedForms: forms.slice(0, 20),
    cookieIssues: cookieIssues.slice(0, 20),
    tlsIssues: tlsIssues.slice(0, 10),
  };
}

// ═══════════════════════════════════════════════════════════════════════
// PDF RENDERING
// ═══════════════════════════════════════════════════════════════════════

/**
 * Render the "Active Scan Results" section in the DI report.
 * Shows tool execution summary with evidence.
 */
export function renderToolResultsSection(
  doc: jsPDF,
  autoTable: any,
  summary: ActiveScanSummary,
  x: number,
  y: number,
  width: number,
  checkPageBreak: (y: number, needed?: number) => number,
): number {
  const margin = x;

  // Tool breakdown table
  if (summary.toolBreakdown.length > 0) {
    y = checkPageBreak(y, 30);
    doc.setFontSize(9);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(15, 23, 42);
    doc.text('Tool Execution Summary', margin, y);
    y += 5;

    autoTable(doc, {
      startY: y,
      head: [['Tool', 'Runs', 'Findings', 'Avg Duration', 'Status']],
      body: summary.toolBreakdown.map(t => [
        t.tool,
        String(t.runs),
        String(t.findings),
        t.avgDuration > 0 ? `${(t.avgDuration / 1000).toFixed(1)}s` : 'N/A',
        t.findings > 0 ? 'Findings' : 'Clean',
      ]),
      theme: 'grid',
      headStyles: { fillColor: [15, 23, 42], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 7, cellPadding: 1.5, textColor: [51, 65, 85] },
      alternateRowStyles: { fillColor: [241, 245, 249] },
      margin: { left: margin, right: margin },
      columnStyles: {
        0: { fontStyle: 'bold' },
        4: { cellWidth: 20 },
      },
      didParseCell: (data: any) => {
        if (data.section === 'body' && data.column.index === 4) {
          const text = String(data.cell.text);
          if (text === 'Findings') { data.cell.styles.textColor = [220, 38, 38]; data.cell.styles.fontStyle = 'bold'; }
          else { data.cell.styles.textColor = [22, 163, 74]; }
        }
      },
    });
    y = (doc as any).lastAutoTable.finalY + 5;
  }

  // Top findings with evidence
  if (summary.topFindings.length > 0) {
    y = checkPageBreak(y, 30);
    doc.setFontSize(9);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(15, 23, 42);
    doc.text(`Key Findings from Active Scanning (${summary.topFindings.length})`, margin, y);
    y += 5;

    autoTable(doc, {
      startY: y,
      head: [['Sev', 'Tool', 'Finding', 'Target', 'Evidence']],
      body: summary.topFindings.slice(0, 15).map(f => [
        f.severity.toUpperCase(),
        f.tool,
        f.finding.length > 50 ? f.finding.substring(0, 47) + '...' : f.finding,
        f.target.length > 30 ? f.target.substring(0, 27) + '...' : f.target,
        f.evidence ? (f.evidence.length > 40 ? f.evidence.substring(0, 37) + '...' : f.evidence) : 'See details',
      ]),
      theme: 'grid',
      headStyles: { fillColor: [15, 23, 42], textColor: [255, 255, 255], fontSize: 6.5, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 6, cellPadding: 1.5, textColor: [51, 65, 85] },
      alternateRowStyles: { fillColor: [241, 245, 249] },
      margin: { left: margin, right: margin },
      columnStyles: {
        0: { cellWidth: 16 },
        1: { cellWidth: 20 },
        4: { cellWidth: 40, fontStyle: 'italic' },
      },
      didParseCell: (data: any) => {
        if (data.section === 'body' && data.column.index === 0) {
          const text = String(data.cell.text);
          if (text === 'CRITICAL') { data.cell.styles.textColor = [153, 27, 27]; data.cell.styles.fontStyle = 'bold'; }
          else if (text === 'HIGH') { data.cell.styles.textColor = [220, 38, 38]; data.cell.styles.fontStyle = 'bold'; }
          else if (text === 'MEDIUM') { data.cell.styles.textColor = [234, 88, 12]; }
        }
      },
    });
    y = (doc as any).lastAutoTable.finalY + 5;
  }

  return y;
}

/**
 * Render the "Web Security Crawl" section in the DI report.
 */
export function renderWebCrawlSection(
  doc: jsPDF,
  autoTable: any,
  summary: WebCrawlSummary,
  x: number,
  y: number,
  width: number,
  checkPageBreak: (y: number, needed?: number) => number,
): number {
  const margin = x;

  // Overview stats
  y = checkPageBreak(y, 20);
  doc.setFontSize(8);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(51, 65, 85);
  doc.text(
    `Crawled ${summary.totalPagesCrawled} pages | Avg response: ${summary.averageResponseTime}ms | ` +
    `${summary.missingHeaders.length} header categories with gaps`,
    margin, y
  );
  y += 6;

  // Security header compliance table
  if (summary.missingHeaders.length > 0) {
    y = checkPageBreak(y, 30);
    doc.setFontSize(9);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(15, 23, 42);
    doc.text('Security Header Compliance', margin, y);
    y += 5;

    autoTable(doc, {
      startY: y,
      head: [['Security Header', 'Missing From', '% Non-Compliant', 'Risk']],
      body: summary.missingHeaders.map(h => {
        const risk = h.percentage >= 80 ? 'HIGH' : h.percentage >= 50 ? 'MEDIUM' : 'LOW';
        return [
          h.header,
          `${h.count} / ${summary.totalPagesCrawled} pages`,
          `${h.percentage}%`,
          risk,
        ];
      }),
      theme: 'grid',
      headStyles: { fillColor: [15, 23, 42], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 7, cellPadding: 1.5, textColor: [51, 65, 85] },
      alternateRowStyles: { fillColor: [241, 245, 249] },
      margin: { left: margin, right: margin },
      didParseCell: (data: any) => {
        if (data.section === 'body' && data.column.index === 3) {
          const text = String(data.cell.text);
          if (text === 'HIGH') { data.cell.styles.textColor = [220, 38, 38]; data.cell.styles.fontStyle = 'bold'; }
          else if (text === 'MEDIUM') { data.cell.styles.textColor = [234, 88, 12]; }
          else { data.cell.styles.textColor = [22, 163, 74]; }
        }
      },
    });
    y = (doc as any).lastAutoTable.finalY + 5;
  }

  // Cookie security issues
  if (summary.cookieIssues.length > 0) {
    y = checkPageBreak(y, 20);
    doc.setFontSize(9);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(15, 23, 42);
    doc.text(`Cookie Security Issues (${summary.cookieIssues.length})`, margin, y);
    y += 5;

    autoTable(doc, {
      startY: y,
      head: [['URL', 'Issue']],
      body: summary.cookieIssues.slice(0, 10).map(c => [
        c.url.length > 50 ? c.url.substring(0, 47) + '...' : c.url,
        c.issue,
      ]),
      theme: 'grid',
      headStyles: { fillColor: [146, 64, 14], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 6.5, cellPadding: 1.5, textColor: [51, 65, 85] },
      alternateRowStyles: { fillColor: [255, 247, 237] },
      margin: { left: margin, right: margin },
    });
    y = (doc as any).lastAutoTable.finalY + 5;
  }

  // TLS issues
  if (summary.tlsIssues.length > 0) {
    y = checkPageBreak(y, 20);
    doc.setFontSize(9);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(15, 23, 42);
    doc.text(`TLS/SSL Issues (${summary.tlsIssues.length})`, margin, y);
    y += 5;

    autoTable(doc, {
      startY: y,
      head: [['URL', 'Issue']],
      body: summary.tlsIssues.map(t => [
        t.url.length > 50 ? t.url.substring(0, 47) + '...' : t.url,
        t.issue,
      ]),
      theme: 'grid',
      headStyles: { fillColor: [153, 27, 27], textColor: [255, 255, 255], fontSize: 7, fontStyle: 'bold', cellPadding: 2 },
      bodyStyles: { fontSize: 6.5, cellPadding: 1.5, textColor: [51, 65, 85] },
      alternateRowStyles: { fillColor: [254, 242, 242] },
      margin: { left: margin, right: margin },
    });
    y = (doc as any).lastAutoTable.finalY + 5;
  }

  return y;
}
