/**
 * Client-Side Engagement Report PDF Generator
 * 
 * Uses jsPDF to generate PDFs entirely in the browser, eliminating
 * the need for server-side Puppeteer/Chromium (which causes OOM in
 * memory-constrained containers like Manus 256MB).
 * 
 * The server-side Puppeteer path remains as a fallback for DO/AWS
 * deployments with more memory.
 */

import { marked } from 'marked';

let _jsPDF: typeof import('jspdf').default | null = null;
let _autoTable: typeof import('jspdf-autotable').default | null = null;

async function loadPdfLibs() {
  if (!_jsPDF) _jsPDF = (await import('jspdf')).default;
  if (!_autoTable) _autoTable = (await import('jspdf-autotable')).default;
  return { jsPDF: _jsPDF, autoTable: _autoTable };
}

interface ReportMeta {
  title: string;
  preparedFor: string;
  preparedBy: string;
  reportType: string;
  generatedAt: string;
}

// Simple markdown token parser for PDF rendering
interface PdfToken {
  type: 'heading' | 'paragraph' | 'list' | 'table' | 'code' | 'hr' | 'blockquote';
  level?: number; // for headings
  text?: string;
  items?: string[]; // for lists
  ordered?: boolean;
  rows?: string[][]; // for tables
  headers?: string[]; // for table headers
}

function parseMarkdownTokens(markdown: string): PdfToken[] {
  const tokens: PdfToken[] = [];
  const lines = markdown.split('\n');
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Headings
    const headingMatch = line.match(/^(#{1,6})\s+(.+)/);
    if (headingMatch) {
      tokens.push({ type: 'heading', level: headingMatch[1].length, text: stripMd(headingMatch[2]) });
      i++;
      continue;
    }

    // Horizontal rule
    if (/^---+$|^\*\*\*+$|^___+$/.test(line.trim())) {
      tokens.push({ type: 'hr' });
      i++;
      continue;
    }

    // Table
    if (line.includes('|') && i + 1 < lines.length && /^\|?\s*[-:]+/.test(lines[i + 1])) {
      const headers = line.split('|').map(c => stripMd(c.trim())).filter(c => c);
      i += 2; // skip header + separator
      const rows: string[][] = [];
      while (i < lines.length && lines[i].includes('|')) {
        const row = lines[i].split('|').map(c => stripMd(c.trim())).filter(c => c);
        if (row.length > 0) rows.push(row);
        i++;
      }
      tokens.push({ type: 'table', headers, rows });
      continue;
    }

    // Code block
    if (line.trim().startsWith('```')) {
      i++;
      const codeLines: string[] = [];
      while (i < lines.length && !lines[i].trim().startsWith('```')) {
        codeLines.push(lines[i]);
        i++;
      }
      i++; // skip closing ```
      tokens.push({ type: 'code', text: codeLines.join('\n') });
      continue;
    }

    // Blockquote
    if (line.trim().startsWith('>')) {
      const quoteLines: string[] = [];
      while (i < lines.length && lines[i].trim().startsWith('>')) {
        quoteLines.push(lines[i].replace(/^>\s?/, ''));
        i++;
      }
      tokens.push({ type: 'blockquote', text: stripMd(quoteLines.join('\n')) });
      continue;
    }

    // Unordered list
    if (/^\s*[-*+]\s+/.test(line)) {
      const items: string[] = [];
      while (i < lines.length && /^\s*[-*+]\s+/.test(lines[i])) {
        items.push(stripMd(lines[i].replace(/^\s*[-*+]\s+/, '')));
        i++;
      }
      tokens.push({ type: 'list', items, ordered: false });
      continue;
    }

    // Ordered list
    if (/^\s*\d+\.\s+/.test(line)) {
      const items: string[] = [];
      while (i < lines.length && /^\s*\d+\.\s+/.test(lines[i])) {
        items.push(stripMd(lines[i].replace(/^\s*\d+\.\s+/, '')));
        i++;
      }
      tokens.push({ type: 'list', items, ordered: true });
      continue;
    }

    // Paragraph (collect consecutive non-empty lines)
    if (line.trim()) {
      const paraLines: string[] = [];
      while (i < lines.length && lines[i].trim() && !lines[i].match(/^#{1,6}\s/) && !lines[i].trim().startsWith('```') && !lines[i].trim().startsWith('>') && !/^\s*[-*+]\s+/.test(lines[i]) && !/^\s*\d+\.\s+/.test(lines[i]) && !(lines[i].includes('|') && i + 1 < lines.length && /^\|?\s*[-:]+/.test(lines[i + 1])) && !/^---+$|^\*\*\*+$|^___+$/.test(lines[i].trim())) {
        paraLines.push(lines[i]);
        i++;
      }
      tokens.push({ type: 'paragraph', text: stripMd(paraLines.join(' ')) });
      continue;
    }

    // Empty line
    i++;
  }

  return tokens;
}

function stripMd(text: string): string {
  return text
    .replace(/\*\*(.+?)\*\*/g, '$1')
    .replace(/\*(.+?)\*/g, '$1')
    .replace(/__(.+?)__/g, '$1')
    .replace(/_(.+?)_/g, '$1')
    .replace(/`(.+?)`/g, '$1')
    .replace(/\[(.+?)\]\(.+?\)/g, '$1')
    .replace(/!\[.*?\]\(.+?\)/g, '[image]');
}

/**
 * Generate a professional PDF from engagement report markdown, entirely client-side.
 */
export async function exportEngagementReportPdf(
  markdown: string,
  meta: ReportMeta
): Promise<void> {
  const { jsPDF, autoTable } = await loadPdfLibs();
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 18;
  const contentWidth = pageWidth - margin * 2;
  let y = margin;

  const dateStr = new Date(meta.generatedAt).toLocaleDateString('en-US', {
    year: 'numeric', month: 'long', day: 'numeric'
  });

  // ═══════════════════════════════════════════════════════════════════════
  // COVER PAGE
  // ═══════════════════════════════════════════════════════════════════════
  // Dark header band
  doc.setFillColor(15, 23, 42); // slate-900
  doc.rect(0, 0, pageWidth, 85, 'F');

  // Title
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(24);
  doc.setTextColor(255, 255, 255);
  const titleLines = doc.splitTextToSize(meta.title, contentWidth);
  doc.text(titleLines, margin, 35);

  // Classification
  doc.setFontSize(10);
  doc.setTextColor(248, 113, 113); // red-400
  doc.text('CONFIDENTIAL — Security Assessment Report', margin, 70);

  // Meta info below header band
  doc.setTextColor(51, 65, 85); // slate-700
  doc.setFontSize(11);
  doc.setFont('helvetica', 'normal');
  y = 100;
  doc.text(`Client: ${meta.preparedFor}`, margin, y); y += 7;
  doc.text(`Prepared by: ${meta.preparedBy}`, margin, y); y += 7;
  doc.text(`Assessment Type: ${formatReportType(meta.reportType)}`, margin, y); y += 7;
  doc.text(`Report Date: ${dateStr}`, margin, y); y += 7;

  // Footer on cover
  doc.setFontSize(8);
  doc.setTextColor(148, 163, 184);
  doc.text('Ace of Cloud LLC — aceofcloud.com', margin, pageHeight - 15);
  doc.text('CONFIDENTIAL', pageWidth - margin - 30, pageHeight - 15);

  // ═══════════════════════════════════════════════════════════════════════
  // CONTENT PAGES
  // ═══════════════════════════════════════════════════════════════════════
  doc.addPage();
  y = margin;

  const tokens = parseMarkdownTokens(markdown);

  function checkPageBreak(needed: number = 25): void {
    if (y + needed > pageHeight - 25) {
      doc.addPage();
      y = margin;
    }
  }

  for (const token of tokens) {
    switch (token.type) {
      case 'heading': {
        const level = token.level || 1;
        checkPageBreak(level <= 2 ? 20 : 14);
        
        if (level === 1) {
          y += 6;
          doc.setFillColor(241, 245, 249); // slate-100
          doc.rect(margin - 2, y - 5, contentWidth + 4, 10, 'F');
          doc.setFont('helvetica', 'bold');
          doc.setFontSize(16);
          doc.setTextColor(15, 23, 42);
          doc.text(token.text || '', margin, y + 2);
          y += 14;
        } else if (level === 2) {
          y += 4;
          doc.setFont('helvetica', 'bold');
          doc.setFontSize(13);
          doc.setTextColor(30, 41, 59);
          doc.text(token.text || '', margin, y);
          y += 10;
        } else if (level === 3) {
          y += 3;
          doc.setFont('helvetica', 'bold');
          doc.setFontSize(11);
          doc.setTextColor(51, 65, 85);
          doc.text(token.text || '', margin, y);
          y += 8;
        } else {
          y += 2;
          doc.setFont('helvetica', 'bold');
          doc.setFontSize(10);
          doc.setTextColor(71, 85, 105);
          doc.text(token.text || '', margin, y);
          y += 7;
        }
        break;
      }

      case 'paragraph': {
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(10);
        doc.setTextColor(30, 41, 59);
        const lines = doc.splitTextToSize(token.text || '', contentWidth);
        checkPageBreak(lines.length * 4.5);
        doc.text(lines, margin, y);
        y += lines.length * 4.5 + 4;
        break;
      }

      case 'list': {
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(10);
        doc.setTextColor(30, 41, 59);
        const items = token.items || [];
        for (let idx = 0; idx < items.length; idx++) {
          const prefix = token.ordered ? `${idx + 1}.` : '•';
          const itemText = `${prefix} ${items[idx]}`;
          const itemLines = doc.splitTextToSize(itemText, contentWidth - 6);
          checkPageBreak(itemLines.length * 4.5);
          doc.text(itemLines, margin + 4, y);
          y += itemLines.length * 4.5 + 1.5;
        }
        y += 3;
        break;
      }

      case 'table': {
        checkPageBreak(30);
        const headers = token.headers || [];
        const rows = token.rows || [];
        if (headers.length > 0 && rows.length > 0) {
          autoTable(doc, {
            startY: y,
            head: [headers],
            body: rows,
            margin: { left: margin, right: margin },
            styles: { fontSize: 8, cellPadding: 2.5, textColor: [30, 41, 59] },
            headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontStyle: 'bold', fontSize: 8 },
            alternateRowStyles: { fillColor: [248, 250, 252] },
            tableWidth: 'auto',
          });
          y = (doc as any).lastAutoTable.finalY + 6;
        }
        break;
      }

      case 'code': {
        const codeText = token.text || '';
        const codeLines = codeText.split('\n');
        const blockHeight = Math.min(codeLines.length * 3.8 + 8, 80);
        checkPageBreak(blockHeight);

        // Dark background
        doc.setFillColor(30, 41, 59);
        doc.roundedRect(margin, y - 2, contentWidth, blockHeight, 2, 2, 'F');

        doc.setFont('courier', 'normal');
        doc.setFontSize(7.5);
        doc.setTextColor(226, 232, 240);
        let codeY = y + 4;
        for (const codeLine of codeLines.slice(0, 18)) { // limit to prevent overflow
          if (codeY > y + blockHeight - 4) break;
          doc.text(codeLine.substring(0, 90), margin + 4, codeY);
          codeY += 3.8;
        }
        if (codeLines.length > 18) {
          doc.text(`... (${codeLines.length - 18} more lines)`, margin + 4, codeY);
        }
        y += blockHeight + 4;
        break;
      }

      case 'blockquote': {
        doc.setFont('helvetica', 'italic');
        doc.setFontSize(10);
        doc.setTextColor(71, 85, 105);
        const quoteLines = doc.splitTextToSize(token.text || '', contentWidth - 10);
        const quoteHeight = quoteLines.length * 4.5 + 6;
        checkPageBreak(quoteHeight);

        // Left border
        doc.setFillColor(148, 163, 184);
        doc.rect(margin, y - 1, 2, quoteHeight, 'F');
        // Background
        doc.setFillColor(248, 250, 252);
        doc.rect(margin + 3, y - 1, contentWidth - 3, quoteHeight, 'F');

        doc.text(quoteLines, margin + 6, y + 3);
        y += quoteHeight + 4;
        break;
      }

      case 'hr': {
        checkPageBreak(8);
        doc.setDrawColor(203, 213, 225);
        doc.setLineWidth(0.3);
        doc.line(margin, y + 2, pageWidth - margin, y + 2);
        y += 8;
        break;
      }
    }
  }

  // ═══════════════════════════════════════════════════════════════════════
  // FOOTER ON ALL PAGES
  // ═══════════════════════════════════════════════════════════════════════
  const pageCount = (doc as any).internal.getNumberOfPages();
  for (let i = 2; i <= pageCount; i++) { // skip cover page
    doc.setPage(i);
    doc.setFontSize(7);
    doc.setTextColor(148, 163, 184);
    doc.text(`Page ${i - 1} of ${pageCount - 1}`, pageWidth - 35, pageHeight - 8);
    doc.text('CONFIDENTIAL — Ace of Cloud LLC', margin, pageHeight - 8);
  }

  // Save
  const safeTitle = meta.title.replace(/[^a-zA-Z0-9_-]/g, '_').substring(0, 60);
  doc.save(`${safeTitle}_${new Date().toISOString().slice(0, 10)}.pdf`);
}

function formatReportType(type: string): string {
  return type
    .replace(/_/g, ' ')
    .replace(/\b\w/g, c => c.toUpperCase());
}
