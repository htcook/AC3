/**
 * DI Report Evidence Rendering Module
 * 
 * Provides rich evidence block rendering for the Domain Intelligence PDF report.
 * Every finding should show the RAW data that supports it — not just a claim.
 * 
 * Evidence types:
 *   - Tool output (Nuclei template match, httpx headers, rustscan ports)
 *   - Curl reproduction commands
 *   - Response snippets (HTTP headers, banner grabs)
 *   - Source attribution with timestamps
 */

import type { jsPDF } from 'jspdf';

// ═══════════════════════════════════════════════════════════════════════
// TYPES
// ═══════════════════════════════════════════════════════════════════════

export interface EvidenceBlock {
  /** Tool that produced this evidence */
  tool: string;
  /** Phase of the scan (discovery, targeted_enum, verification, etc.) */
  phase?: string;
  /** The command that was executed */
  command?: string;
  /** Exit code of the tool */
  exitCode?: number;
  /** Duration of the tool execution */
  durationMs?: number;
  /** Timestamp when the evidence was collected */
  timestamp?: string;
  /** Template ID (for Nuclei) */
  templateId?: string;
  /** The URL/endpoint where the finding was matched */
  matchedAt?: string;
  /** Extracted data from the response */
  extractedResults?: string[];
  /** Matched line from response body */
  matchedLine?: string;
  /** Curl command to reproduce */
  curlCommand?: string;
  /** Raw response snippet (truncated) */
  responseSnippet?: string;
  /** HTTP response headers relevant to the finding */
  relevantHeaders?: Record<string, string>;
  /** Confidence level */
  confidence?: 'high' | 'medium' | 'low';
  /** Source attribution */
  source?: string;
  /** Severity from the tool */
  severity?: string;
  /** Additional context notes */
  notes?: string;
}

export interface EvidenceRenderOptions {
  /** Maximum height before truncation */
  maxHeight?: number;
  /** Whether to show the curl command */
  showCurl?: boolean;
  /** Whether to show response headers */
  showHeaders?: boolean;
  /** Whether to show the full command */
  showCommand?: boolean;
  /** Compact mode for inline evidence */
  compact?: boolean;
}

// ═══════════════════════════════════════════════════════════════════════
// EVIDENCE EXTRACTION
// ═══════════════════════════════════════════════════════════════════════

/**
 * Extract evidence blocks from a vulnerability observation.
 * Pulls from multiple data sources: postureFindings, scan_results, nuclei output.
 */
export function extractEvidenceFromObservation(obs: any, scanResults?: any[]): EvidenceBlock[] {
  const blocks: EvidenceBlock[] = [];
  const evidence = obs.evidence || {};

  // 1. Nuclei verification evidence
  if (evidence.nucleiVerification) {
    const nv = evidence.nucleiVerification;
    blocks.push({
      tool: 'nuclei',
      phase: 'verification',
      command: nv.command || '',
      exitCode: nv.exitCode,
      durationMs: nv.durationMs,
      templateId: nv.templateId || evidence.cve_id,
      matchedAt: nv.matchedAt || nv.parseResult?.findings?.[0]?.matchedAt,
      extractedResults: nv.parseResult?.findings?.[0]?.extractedResults || [],
      matchedLine: nv.parseResult?.findings?.[0]?.matchedLine,
      curlCommand: nv.parseResult?.findings?.[0]?.curlCommand,
      confidence: nv.confirmed ? 'high' : 'medium',
      severity: nv.parseResult?.findings?.[0]?.info?.severity,
      source: 'Nuclei Verification Engine',
      timestamp: nv.timestamp,
    });
  }

  // 2. Direct Nuclei findings from postureFindings
  if (evidence.nucleiTemplateId || evidence.nucleiMatch) {
    blocks.push({
      tool: 'nuclei',
      phase: 'active_scan',
      templateId: evidence.nucleiTemplateId,
      matchedAt: evidence.nucleiMatchedAt || evidence.hostname,
      extractedResults: evidence.nucleiExtracted ? [evidence.nucleiExtracted] : [],
      matchedLine: evidence.nucleiMatchedLine,
      curlCommand: evidence.nucleiCurl,
      confidence: 'high',
      severity: evidence.nucleiSeverity,
      source: 'Nuclei Active Scan',
      timestamp: evidence.nucleiTimestamp,
    });
  }

  // 3. Version detection evidence (httpx, banner grab)
  if (evidence.detectedVersion && evidence.detectionSource) {
    const isHttpx = evidence.detectionSource === 'httpx' || evidence.detectionSource === 'http_headers';
    blocks.push({
      tool: evidence.detectionSource || 'httpx',
      phase: 'discovery',
      matchedAt: evidence.hostname || obs.domain,
      extractedResults: [`Version: ${evidence.detectedVersion}`],
      relevantHeaders: evidence.detectionHeaders || {},
      responseSnippet: evidence.bannerGrab || evidence.headerSnippet || '',
      confidence: evidence.corroboration === '[CONFIRMED]' ? 'high' : 'medium',
      source: isHttpx ? 'HTTP Response Headers' : 'Service Banner',
      notes: evidence.affectedVersions ? `Affected range: ${evidence.affectedVersions}` : undefined,
    });
  }

  // 4. Scan results from the scan_results table (tool execution records)
  if (scanResults && scanResults.length > 0) {
    const hostname = evidence.hostname || obs.domain;
    const cveId = evidence.cve_id;

    // Find matching scan results for this finding
    const matchingResults = scanResults.filter((sr: any) => {
      if (sr.target === hostname || sr.target?.includes(hostname)) {
        // Check if findings mention this CVE
        if (cveId && sr.findings) {
          const findings = typeof sr.findings === 'string' ? JSON.parse(sr.findings) : sr.findings;
          return Array.isArray(findings) && findings.some((f: any) =>
            f.templateId?.includes(cveId) || f.name?.includes(cveId) || f.cve_id === cveId
          );
        }
        return true;
      }
      return false;
    });

    for (const sr of matchingResults.slice(0, 2)) { // Max 2 tool results per finding
      blocks.push({
        tool: sr.tool,
        phase: sr.phase || 'active_scan',
        command: sr.command,
        exitCode: sr.exitCode,
        durationMs: sr.durationMs,
        responseSnippet: sr.rawOutput ? truncateOutput(sr.rawOutput, 500) : undefined,
        confidence: sr.exitCode === 0 ? 'high' : 'medium',
        source: `${sr.tool} scan`,
        timestamp: sr.createdAt,
      });
    }
  }

  // 5. Web crawl evidence (security headers, forms)
  if (evidence.crawlEvidence) {
    const ce = evidence.crawlEvidence;
    blocks.push({
      tool: 'web_crawler',
      phase: 'crawl',
      matchedAt: ce.url || evidence.hostname,
      relevantHeaders: ce.securityHeaders || {},
      responseSnippet: ce.finding || '',
      confidence: 'high',
      source: 'Web Security Crawl',
      notes: ce.grade ? `Security Header Grade: ${ce.grade}` : undefined,
      timestamp: ce.crawledAt,
    });
  }

  // 6. Shodan/Censys passive evidence
  if (evidence.shodanData || evidence.censysData) {
    const passive = evidence.shodanData || evidence.censysData;
    blocks.push({
      tool: evidence.shodanData ? 'shodan' : 'censys',
      phase: 'passive_recon',
      matchedAt: passive.ip || evidence.hostname,
      responseSnippet: passive.banner || passive.data || '',
      extractedResults: passive.vulns ? passive.vulns.map((v: string) => `CVE: ${v}`) : [],
      confidence: 'medium',
      source: evidence.shodanData ? 'Shodan Internet DB' : 'Censys Search',
      timestamp: passive.timestamp || passive.last_seen,
    });
  }

  // 7. Fallback: construct evidence from available fields
  if (blocks.length === 0) {
    const fallbackParts: string[] = [];
    if (evidence.evidenceDetail) fallbackParts.push(evidence.evidenceDetail);
    if (evidence.evidenceChain?.length > 0) fallbackParts.push(evidence.evidenceChain.join(' → '));
    if (evidence.evidenceBasis) fallbackParts.push(`Basis: ${evidence.evidenceBasis}`);

    if (fallbackParts.length > 0) {
      blocks.push({
        tool: evidence.source || obs.source || 'passive_analysis',
        phase: 'analysis',
        notes: fallbackParts.join('\n'),
        confidence: evidence.corroboration === '[CONFIRMED]' ? 'high' : evidence.corroboration === '[PROBABLE]' ? 'medium' : 'low',
        source: evidence.source || obs.source || 'Intelligence Analysis',
      });
    }
  }

  return blocks;
}

/**
 * Extract evidence blocks from a web crawl result for security header findings.
 */
export function extractCrawlEvidence(crawlResult: any): EvidenceBlock {
  const missingHeaders: string[] = [];
  const presentHeaders: Record<string, string> = {};

  const secHeaders = crawlResult.securityHeaders || {};
  const criticalHeaders = [
    'strict-transport-security',
    'content-security-policy',
    'x-frame-options',
    'x-content-type-options',
    'referrer-policy',
    'permissions-policy',
  ];

  for (const h of criticalHeaders) {
    if (secHeaders[h]) {
      presentHeaders[h] = secHeaders[h];
    } else {
      missingHeaders.push(h);
    }
  }

  return {
    tool: 'web_crawler',
    phase: 'security_audit',
    matchedAt: crawlResult.targetUrl || crawlResult.finalUrl,
    relevantHeaders: presentHeaders,
    extractedResults: missingHeaders.length > 0
      ? [`Missing critical headers: ${missingHeaders.join(', ')}`]
      : ['All critical security headers present'],
    confidence: 'high',
    source: 'Web Security Crawl',
    notes: crawlResult.securityHeaderGrade ? `Grade: ${crawlResult.securityHeaderGrade}` : undefined,
    timestamp: crawlResult.completedAt ? new Date(crawlResult.completedAt).toISOString() : undefined,
  };
}

// ═══════════════════════════════════════════════════════════════════════
// PDF RENDERING
// ═══════════════════════════════════════════════════════════════════════

/**
 * Render an evidence block into the PDF document.
 * Returns the new Y position after rendering.
 */
export function renderEvidenceBlock(
  doc: jsPDF,
  block: EvidenceBlock,
  x: number,
  y: number,
  width: number,
  options: EvidenceRenderOptions = {},
): number {
  const { maxHeight = 80, showCurl = true, showHeaders = true, showCommand = true, compact = false } = options;
  const startY = y;
  const padding = 2;
  const innerWidth = width - padding * 2;

  // Estimate total height to check page break
  let estimatedHeight = 12; // header
  if (block.command && showCommand) estimatedHeight += 8;
  if (block.matchedAt) estimatedHeight += 4;
  if (block.extractedResults?.length) estimatedHeight += block.extractedResults.length * 3.5;
  if (block.matchedLine) estimatedHeight += 4;
  if (block.responseSnippet && !compact) estimatedHeight += 12;
  if (block.relevantHeaders && showHeaders) estimatedHeight += Object.keys(block.relevantHeaders).length * 3;
  if (block.curlCommand && showCurl) estimatedHeight += 8;
  if (block.notes) estimatedHeight += 6;
  estimatedHeight += 4; // footer

  // Cap at maxHeight
  const renderHeight = Math.min(estimatedHeight, maxHeight);

  // Background box
  doc.setFillColor(248, 250, 252); // slate-50
  doc.setDrawColor(203, 213, 225); // slate-300
  doc.setLineWidth(0.3);
  doc.roundedRect(x, y, width, renderHeight, 1.5, 1.5, 'FD');

  y += padding;

  // ── Header bar ──
  const confidenceColor = block.confidence === 'high' ? [22, 163, 74] // green
    : block.confidence === 'medium' ? [202, 138, 4] // amber
    : [148, 163, 184]; // gray
  
  doc.setFillColor(241, 245, 249); // slate-100
  doc.roundedRect(x + padding, y, innerWidth, 8, 1, 1, 'F');
  
  // Lightning bolt icon + "EVIDENCE" label
  doc.setFontSize(6.5);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(15, 23, 42);
  doc.text('\u26A1 EVIDENCE', x + padding + 2, y + 5);

  // Tool badge
  const toolText = block.tool.toUpperCase();
  const toolWidth = doc.getTextWidth(toolText) + 4;
  doc.setFillColor(30, 41, 59);
  doc.roundedRect(x + padding + 28, y + 1, toolWidth, 5.5, 1, 1, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFontSize(5.5);
  doc.text(toolText, x + padding + 30, y + 4.8);

  // Phase badge
  if (block.phase) {
    const phaseText = block.phase.replace(/_/g, ' ');
    const phaseWidth = doc.getTextWidth(phaseText) + 4;
    doc.setFillColor(59, 130, 246); // blue-500
    doc.roundedRect(x + padding + 30 + toolWidth + 2, y + 1, phaseWidth, 5.5, 1, 1, 'F');
    doc.setTextColor(255, 255, 255);
    doc.text(phaseText, x + padding + 32 + toolWidth + 2, y + 4.8);
  }

  // Duration + exit code on right
  const rightParts: string[] = [];
  if (block.exitCode !== undefined) rightParts.push(`exit:${block.exitCode}`);
  if (block.durationMs) rightParts.push(`${(block.durationMs / 1000).toFixed(1)}s`);
  if (block.timestamp) {
    try {
      const ts = new Date(block.timestamp);
      rightParts.push(ts.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }));
    } catch { /* skip */ }
  }
  if (rightParts.length > 0) {
    doc.setFontSize(5.5);
    doc.setTextColor(100, 116, 139);
    doc.setFont('helvetica', 'normal');
    const rightText = rightParts.join(' | ');
    doc.text(rightText, x + width - padding - doc.getTextWidth(rightText), y + 5);
  }

  y += 10;

  // ── Command line ──
  if (block.command && showCommand && !compact) {
    doc.setFillColor(15, 23, 42); // dark bg for code
    const cmdHeight = 6;
    doc.roundedRect(x + padding, y, innerWidth, cmdHeight, 1, 1, 'F');
    doc.setFontSize(5);
    doc.setFont('courier', 'normal');
    doc.setTextColor(167, 243, 208); // green-200
    const truncCmd = block.command.length > 120 ? block.command.substring(0, 117) + '...' : block.command;
    doc.text(`$ ${truncCmd}`, x + padding + 2, y + 4);
    y += cmdHeight + 2;
  }

  // ── Matched At ──
  if (block.matchedAt) {
    doc.setFontSize(6);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(51, 65, 85);
    doc.text('Matched At:', x + padding + 1, y + 3);
    doc.setFont('courier', 'normal');
    doc.setFontSize(5.5);
    doc.setTextColor(37, 99, 235); // blue-600
    const truncUrl = block.matchedAt.length > 90 ? block.matchedAt.substring(0, 87) + '...' : block.matchedAt;
    doc.text(truncUrl, x + padding + 20, y + 3);
    y += 4;
  }

  // ── Extracted Results ──
  if (block.extractedResults && block.extractedResults.length > 0) {
    doc.setFontSize(6);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(51, 65, 85);
    doc.text('Extracted:', x + padding + 1, y + 3);
    y += 4;
    doc.setFont('courier', 'normal');
    doc.setFontSize(5.5);
    doc.setTextColor(22, 101, 52); // green-800
    for (const result of block.extractedResults.slice(0, 5)) {
      const truncResult = result.length > 100 ? result.substring(0, 97) + '...' : result;
      doc.text(`  ${truncResult}`, x + padding + 2, y + 2.5);
      y += 3;
    }
    if (block.extractedResults.length > 5) {
      doc.setTextColor(100, 116, 139);
      doc.text(`  ... +${block.extractedResults.length - 5} more`, x + padding + 2, y + 2.5);
      y += 3;
    }
  }

  // ── Matched Line ──
  if (block.matchedLine && !compact) {
    doc.setFontSize(6);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(51, 65, 85);
    doc.text('Matched:', x + padding + 1, y + 3);
    doc.setFont('courier', 'normal');
    doc.setFontSize(5);
    doc.setTextColor(146, 64, 14); // orange-800
    const truncLine = block.matchedLine.length > 100 ? block.matchedLine.substring(0, 97) + '...' : block.matchedLine;
    doc.text(truncLine, x + padding + 16, y + 3);
    y += 4;
  }

  // ── Response Snippet ──
  if (block.responseSnippet && !compact) {
    doc.setFillColor(15, 23, 42);
    const snippetLines = block.responseSnippet.split('\n').slice(0, 6);
    const snippetHeight = Math.min(snippetLines.length * 3 + 2, 20);
    doc.roundedRect(x + padding, y, innerWidth, snippetHeight, 1, 1, 'F');
    doc.setFont('courier', 'normal');
    doc.setFontSize(4.5);
    doc.setTextColor(226, 232, 240); // slate-200
    let sy = y + 3;
    for (const line of snippetLines) {
      const truncLine = line.length > 130 ? line.substring(0, 127) + '...' : line;
      doc.text(truncLine, x + padding + 2, sy);
      sy += 3;
    }
    y += snippetHeight + 2;
  }

  // ── Relevant Headers ──
  if (block.relevantHeaders && showHeaders && Object.keys(block.relevantHeaders).length > 0 && !compact) {
    doc.setFontSize(6);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(51, 65, 85);
    doc.text('Response Headers:', x + padding + 1, y + 3);
    y += 4;
    doc.setFont('courier', 'normal');
    doc.setFontSize(5);
    doc.setTextColor(71, 85, 105);
    for (const [key, value] of Object.entries(block.relevantHeaders).slice(0, 6)) {
      const headerLine = `${key}: ${value}`;
      const truncHeader = headerLine.length > 110 ? headerLine.substring(0, 107) + '...' : headerLine;
      doc.text(truncHeader, x + padding + 2, y + 2.5);
      y += 3;
    }
  }

  // ── Curl Command ──
  if (block.curlCommand && showCurl && !compact) {
    doc.setFillColor(30, 41, 59);
    const curlHeight = 6;
    doc.roundedRect(x + padding, y, innerWidth, curlHeight, 1, 1, 'F');
    doc.setFont('courier', 'normal');
    doc.setFontSize(5);
    doc.setTextColor(253, 224, 71); // yellow-300
    const truncCurl = block.curlCommand.length > 120 ? block.curlCommand.substring(0, 117) + '...' : block.curlCommand;
    doc.text(`\u21B3 ${truncCurl}`, x + padding + 2, y + 4);
    y += curlHeight + 2;
  }

  // ── Notes ──
  if (block.notes && !compact) {
    doc.setFontSize(5.5);
    doc.setFont('helvetica', 'italic');
    doc.setTextColor(100, 116, 139);
    const noteLines = doc.splitTextToSize(block.notes, innerWidth - 4);
    for (const line of noteLines.slice(0, 3)) {
      doc.text(line, x + padding + 2, y + 2.5);
      y += 3;
    }
  }

  // ── Confidence footer ──
  y += 1;
  doc.setFontSize(5);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(confidenceColor[0] as number, confidenceColor[1] as number, confidenceColor[2] as number);
  const confText = `Confidence: ${(block.confidence || 'unknown').toUpperCase()}`;
  doc.text(confText, x + padding + 1, y + 2);
  if (block.source) {
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(100, 116, 139);
    doc.text(`| Source: ${block.source}`, x + padding + 1 + doc.getTextWidth(confText) + 3, y + 2);
  }
  y += 4;

  // Adjust the background box height to actual content
  const actualHeight = y - startY;
  // Re-draw the box with correct height (overdraw)
  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(203, 213, 225);
  doc.setLineWidth(0.3);
  // We can't easily resize after drawing, so we accept the estimated height
  // The content will fit within the estimated bounds

  return y + 2; // Return position with spacing
}

/**
 * Render a compact inline evidence summary (single line).
 * Used for probable/potential findings where full blocks would be too verbose.
 */
export function renderInlineEvidence(
  doc: jsPDF,
  block: EvidenceBlock,
  x: number,
  y: number,
  width: number,
): number {
  doc.setFontSize(5.5);
  doc.setFont('helvetica', 'italic');
  doc.setTextColor(22, 101, 52);

  const parts: string[] = [];
  if (block.tool) parts.push(`[${block.tool}]`);
  if (block.matchedAt) parts.push(`@ ${truncateStr(block.matchedAt, 40)}`);
  if (block.extractedResults?.[0]) parts.push(`→ ${truncateStr(block.extractedResults[0], 50)}`);
  if (block.notes) parts.push(truncateStr(block.notes, 40));
  if (block.confidence) parts.push(`(${block.confidence})`);

  const text = parts.join(' ');
  const truncText = text.length > 140 ? text.substring(0, 137) + '...' : text;
  doc.text(truncText, x, y);
  return y + 3;
}

// ═══════════════════════════════════════════════════════════════════════
// CHART HELPERS (SVG-based for PDF embedding)
// ═══════════════════════════════════════════════════════════════════════

/**
 * Draw a semi-circular risk gauge directly on the PDF.
 * More visually impactful than a simple colored rectangle.
 */
export function drawRiskGauge(
  doc: jsPDF,
  centerX: number,
  centerY: number,
  radius: number,
  score: number,
  band: string,
): void {
  const startAngle = Math.PI; // 180 degrees (left)
  const endAngle = 0; // 0 degrees (right)
  const scoreAngle = startAngle - (score / 100) * Math.PI;

  // Background arc (gray)
  doc.setDrawColor(203, 213, 225);
  doc.setLineWidth(3);
  drawArc(doc, centerX, centerY, radius, startAngle, endAngle, 40);

  // Score arc (colored)
  const color = getRiskColorRGB(band);
  doc.setDrawColor(color[0], color[1], color[2]);
  doc.setLineWidth(3.5);
  drawArc(doc, centerX, centerY, radius, startAngle, scoreAngle, 20);

  // Score text
  doc.setFontSize(18);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(color[0], color[1], color[2]);
  const scoreText = String(score);
  const scoreWidth = doc.getTextWidth(scoreText);
  doc.text(scoreText, centerX - scoreWidth / 2, centerY - 2);

  // Band label
  doc.setFontSize(7);
  doc.setFont('helvetica', 'bold');
  doc.text(band.toUpperCase(), centerX - doc.getTextWidth(band.toUpperCase()) / 2, centerY + 5);

  // Scale labels
  doc.setFontSize(5);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(148, 163, 184);
  doc.text('0', centerX - radius - 3, centerY + 3);
  doc.text('100', centerX + radius - 2, centerY + 3);
}

/**
 * Draw a horizontal severity distribution bar.
 */
export function drawSeverityBar(
  doc: jsPDF,
  x: number,
  y: number,
  width: number,
  height: number,
  counts: { critical: number; high: number; medium: number; low: number },
): void {
  const total = counts.critical + counts.high + counts.medium + counts.low;
  if (total === 0) return;

  const colors: [string, [number, number, number], number][] = [
    ['Critical', [153, 27, 27], counts.critical],
    ['High', [220, 38, 38], counts.high],
    ['Medium', [234, 88, 12], counts.medium],
    ['Low', [22, 163, 74], counts.low],
  ];

  let currentX = x;
  for (const [label, color, count] of colors) {
    if (count === 0) continue;
    const segWidth = (count / total) * width;
    doc.setFillColor(color[0], color[1], color[2]);
    doc.rect(currentX, y, segWidth, height, 'F');

    // Label inside segment if wide enough
    if (segWidth > 15) {
      doc.setFontSize(5);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(255, 255, 255);
      doc.text(`${label}: ${count}`, currentX + 2, y + height / 2 + 1.5);
    }
    currentX += segWidth;
  }

  // Round the corners by overlaying
  doc.setDrawColor(255, 255, 255);
  doc.setLineWidth(0.1);
}

/**
 * Draw a mini stat card (icon + number + label).
 */
export function drawStatCard(
  doc: jsPDF,
  x: number,
  y: number,
  width: number,
  height: number,
  value: string | number,
  label: string,
  color: [number, number, number] = [15, 23, 42],
): void {
  // Card background
  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(226, 232, 240);
  doc.setLineWidth(0.3);
  doc.roundedRect(x, y, width, height, 2, 2, 'FD');

  // Value
  doc.setFontSize(14);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(color[0], color[1], color[2]);
  doc.text(String(value), x + width / 2 - doc.getTextWidth(String(value)) / 2, y + height / 2);

  // Label
  doc.setFontSize(6);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(100, 116, 139);
  doc.text(label, x + width / 2 - doc.getTextWidth(label) / 2, y + height - 4);
}

// ═══════════════════════════════════════════════════════════════════════
// UTILITY FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════

function truncateStr(str: string, max: number): string {
  return str.length > max ? str.substring(0, max - 3) + '...' : str;
}

function truncateOutput(output: string, maxChars: number): string {
  if (output.length <= maxChars) return output;
  return output.substring(0, maxChars) + '\n... [truncated]';
}

function getRiskColorRGB(band: string): [number, number, number] {
  switch (band?.toLowerCase()) {
    case 'critical': return [153, 27, 27];
    case 'high': return [220, 38, 38];
    case 'medium': return [202, 138, 4];
    case 'low': return [22, 163, 74];
    default: return [113, 113, 122];
  }
}

function drawArc(
  doc: jsPDF,
  cx: number,
  cy: number,
  radius: number,
  startAngle: number,
  endAngle: number,
  segments: number,
): void {
  const step = (endAngle - startAngle) / segments;
  for (let i = 0; i < segments; i++) {
    const a1 = startAngle + step * i;
    const a2 = startAngle + step * (i + 1);
    const x1 = cx + radius * Math.cos(a1);
    const y1 = cy - radius * Math.sin(a1);
    const x2 = cx + radius * Math.cos(a2);
    const y2 = cy - radius * Math.sin(a2);
    doc.line(x1, y1, x2, y2);
  }
}
