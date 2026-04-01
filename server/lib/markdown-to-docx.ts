/**
 * Markdown-to-DOCX converter for pentest report pipeline.
 * Parses the full markdown output (all 16 sections) and produces a
 * professionally formatted DOCX document.
 */
import * as docx from "docx";

const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  WidthType, AlignmentType, HeadingLevel, BorderStyle, ShadingType,
  PageBreak, Header, Footer, TabStopPosition, TabStopType,
} = docx;

// ── Severity color map ──
const severityColor: Record<string, string> = {
  critical: "FF0000",
  high: "FF6600",
  moderate: "FFAA00",
  medium: "FFAA00",
  low: "3399FF",
  informational: "999999",
  info: "999999",
};

// ── Markdown line parser helpers ──

function isHeading(line: string): { level: number; text: string } | null {
  const m = line.match(/^(#{1,4})\s+(.+)/);
  if (!m) return null;
  return { level: m[1].length, text: m[2].trim() };
}

function isTableSeparator(line: string): boolean {
  return /^\|[\s\-:|]+\|$/.test(line.trim());
}

function isTableRow(line: string): boolean {
  return line.trim().startsWith("|") && line.trim().endsWith("|");
}

function parseTableCells(line: string): string[] {
  return line
    .trim()
    .replace(/^\|/, "")
    .replace(/\|$/, "")
    .split("|")
    .map((c) => c.trim());
}

function isBullet(line: string): { indent: number; text: string } | null {
  const m = line.match(/^(\s*)[-*+]\s+(.+)/);
  if (!m) return null;
  return { indent: Math.floor(m[1].length / 2), text: m[2] };
}

function isNumberedList(line: string): { num: string; text: string } | null {
  const m = line.match(/^\s*(\d+)\.\s+(.+)/);
  if (!m) return null;
  return { num: m[1], text: m[2] };
}

function isBlockquote(line: string): string | null {
  const m = line.match(/^>\s*(.*)/);
  return m ? m[1] : null;
}

function isCodeFence(line: string): boolean {
  return line.trim().startsWith("```");
}

function isHorizontalRule(line: string): boolean {
  return /^---+$/.test(line.trim()) || /^\*\*\*+$/.test(line.trim());
}

/** Parse inline markdown: **bold**, *italic*, `code`, [link](url) */
function parseInline(text: string): docx.TextRun[] {
  const runs: docx.TextRun[] = [];
  // Simple regex-based inline parser
  const regex = /(\*\*(.+?)\*\*|\*(.+?)\*|`(.+?)`|\[(.+?)\]\((.+?)\))/g;
  let lastIndex = 0;
  let match: RegExpExecArray | null;

  while ((match = regex.exec(text)) !== null) {
    // Text before match
    if (match.index > lastIndex) {
      runs.push(new TextRun({ text: text.slice(lastIndex, match.index), size: 20 }));
    }
    if (match[2]) {
      // **bold**
      runs.push(new TextRun({ text: match[2], bold: true, size: 20 }));
    } else if (match[3]) {
      // *italic*
      runs.push(new TextRun({ text: match[3], italics: true, size: 20 }));
    } else if (match[4]) {
      // `code`
      runs.push(new TextRun({ text: match[4], font: "Courier New", size: 18, shading: { type: ShadingType.SOLID, color: "F0F0F0" } as any }));
    } else if (match[5] && match[6]) {
      // [link](url)
      runs.push(new TextRun({ text: match[5], color: "0066CC", underline: { type: "single" as any }, size: 20 }));
    }
    lastIndex = match.index + match[0].length;
  }
  // Remaining text
  if (lastIndex < text.length) {
    runs.push(new TextRun({ text: text.slice(lastIndex), size: 20 }));
  }
  if (runs.length === 0) {
    runs.push(new TextRun({ text, size: 20 }));
  }
  return runs;
}

/** Build a DOCX table from parsed markdown table rows */
function buildTable(headerCells: string[], bodyRows: string[][]): docx.Table {
  const headerRow = new TableRow({
    tableHeader: true,
    children: headerCells.map(
      (text) =>
        new TableCell({
          shading: { type: ShadingType.SOLID, color: "1a1a2e" },
          children: [
            new Paragraph({
              alignment: AlignmentType.CENTER,
              children: [new TextRun({ text, bold: true, color: "FFFFFF", size: 18 })],
            }),
          ],
        })
    ),
  });

  const dataRows = bodyRows.map(
    (cells) =>
      new TableRow({
        children: cells.map((cell) => {
          // Color-code severity cells
          const lower = cell.toLowerCase();
          const color = severityColor[lower];
          return new TableCell({
            children: [
              new Paragraph({
                children: color
                  ? [new TextRun({ text: cell, bold: true, color, size: 18 })]
                  : parseInline(cell).map((r) => {
                      // Downsize table cell text
                      return new TextRun({ ...r, size: 18 } as any);
                    }),
              }),
            ],
          });
        }),
      })
  );

  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows: [headerRow, ...dataRows],
  });
}

export interface DocxConvertOptions {
  title: string;
  preparedFor: string;
  preparedBy: string;
  assessmentType: string;
  reportDate: string;
  reportId?: string;
}

/**
 * Convert a full pentest-pipeline markdown string to a DOCX Buffer.
 */
export async function markdownToDocx(
  markdown: string,
  opts: DocxConvertOptions
): Promise<Buffer> {
  const lines = markdown.split("\n");
  const children: docx.Paragraph[] = [];

  // ── Title page ──
  children.push(
    new Paragraph({ spacing: { before: 3000 }, alignment: AlignmentType.CENTER, children: [] }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 200 },
      children: [new TextRun({ text: opts.title || "Security Assessment Report", bold: true, size: 56, color: "1a1a2e" })],
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 100 },
      children: [new TextRun({ text: `${opts.assessmentType.toUpperCase()} REPORT`, size: 28, color: "666666" })],
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 400 },
      children: [new TextRun({ text: "CONFIDENTIAL — For Authorized Personnel Only", size: 22, color: "CC0000", bold: true })],
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      children: [new TextRun({ text: `Prepared for: ${opts.preparedFor}`, size: 22, color: "444444" })],
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      children: [new TextRun({ text: `Prepared by: ${opts.preparedBy}`, size: 22, color: "444444", italics: true })],
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { before: 200 },
      children: [new TextRun({ text: `Report Date: ${opts.reportDate}`, size: 20, color: "888888" })],
    }),
    ...(opts.reportId
      ? [
          new Paragraph({
            alignment: AlignmentType.CENTER,
            children: [new TextRun({ text: `Report ID: ${opts.reportId}`, size: 18, color: "888888" })],
          }),
        ]
      : []),
    new Paragraph({ children: [new PageBreak()] })
  );

  // ── Parse markdown body ──
  let i = 0;
  let inCodeBlock = false;
  let codeLines: string[] = [];

  // Table accumulator
  let tableHeader: string[] | null = null;
  let tableBody: string[][] = [];

  function flushTable() {
    if (tableHeader) {
      children.push(buildTable(tableHeader, tableBody));
      children.push(new Paragraph({ spacing: { after: 100 }, children: [] }));
      tableHeader = null;
      tableBody = [];
    }
  }

  while (i < lines.length) {
    const line = lines[i];

    // ── Code blocks ──
    if (isCodeFence(line)) {
      if (inCodeBlock) {
        // End code block
        flushTable();
        children.push(
          new Paragraph({
            spacing: { before: 100, after: 100 },
            shading: { type: ShadingType.SOLID, color: "2a2a2a" },
            children: codeLines.map(
              (cl, idx) =>
                new TextRun({
                  text: cl + (idx < codeLines.length - 1 ? "\n" : ""),
                  font: "Courier New",
                  size: 16,
                  color: "E0E0E0",
                })
            ),
          })
        );
        codeLines = [];
        inCodeBlock = false;
      } else {
        flushTable();
        inCodeBlock = true;
      }
      i++;
      continue;
    }

    if (inCodeBlock) {
      codeLines.push(line);
      i++;
      continue;
    }

    // ── Table rows ──
    if (isTableRow(line)) {
      const cells = parseTableCells(line);
      if (isTableSeparator(line)) {
        // Skip separator row
        i++;
        continue;
      }
      if (!tableHeader) {
        // First table row = header
        tableHeader = cells;
      } else {
        tableBody.push(cells);
      }
      i++;
      continue;
    } else {
      flushTable();
    }

    // ── Horizontal rule ──
    if (isHorizontalRule(line)) {
      children.push(
        new Paragraph({
          spacing: { before: 200, after: 200 },
          border: { bottom: { style: BorderStyle.SINGLE, size: 1, color: "CCCCCC" } },
          children: [],
        })
      );
      i++;
      continue;
    }

    // ── Headings ──
    const heading = isHeading(line);
    if (heading) {
      const headingMap: Record<number, (typeof HeadingLevel)[keyof typeof HeadingLevel]> = {
        1: HeadingLevel.HEADING_1,
        2: HeadingLevel.HEADING_1,
        3: HeadingLevel.HEADING_2,
        4: HeadingLevel.HEADING_3,
      };
      // Add page break before top-level sections (## N.)
      if (heading.level <= 2 && /^\d+\./.test(heading.text)) {
        children.push(new Paragraph({ children: [new PageBreak()] }));
      }
      children.push(
        new Paragraph({
          heading: headingMap[heading.level] || HeadingLevel.HEADING_3,
          spacing: { before: heading.level <= 2 ? 400 : 200, after: 100 },
          children: [new TextRun({ text: heading.text, bold: true })],
        })
      );
      i++;
      continue;
    }

    // ── Blockquote ──
    const bq = isBlockquote(line);
    if (bq !== null) {
      children.push(
        new Paragraph({
          spacing: { before: 100, after: 100 },
          indent: { left: 720 },
          border: { left: { style: BorderStyle.SINGLE, size: 6, color: "999999" } },
          children: parseInline(bq),
        })
      );
      i++;
      continue;
    }

    // ── Bullet list ──
    const bullet = isBullet(line);
    if (bullet) {
      children.push(
        new Paragraph({
          bullet: { level: Math.min(bullet.indent, 2) },
          children: parseInline(bullet.text),
        })
      );
      i++;
      continue;
    }

    // ── Numbered list ──
    const numbered = isNumberedList(line);
    if (numbered) {
      children.push(
        new Paragraph({
          spacing: { after: 60 },
          children: [
            new TextRun({ text: `${numbered.num}. `, bold: true, size: 20 }),
            ...parseInline(numbered.text),
          ],
        })
      );
      i++;
      continue;
    }

    // ── Empty line ──
    if (line.trim() === "") {
      i++;
      continue;
    }

    // ── Regular paragraph ──
    children.push(
      new Paragraph({
        spacing: { after: 120 },
        children: parseInline(line),
      })
    );
    i++;
  }

  // Flush any remaining table
  flushTable();

  // ── Build document ──
  const doc = new Document({
    creator: opts.preparedBy || "Ace of Cloud LLC",
    title: opts.title || "Security Assessment Report",
    description: `${opts.assessmentType} Report`,
    styles: {
      default: {
        document: {
          run: { font: "Calibri", size: 20 },
        },
        heading1: {
          run: { font: "Calibri", size: 32, bold: true, color: "1a1a2e" },
          paragraph: { spacing: { before: 360, after: 120 } },
        },
        heading2: {
          run: { font: "Calibri", size: 26, bold: true, color: "333333" },
          paragraph: { spacing: { before: 240, after: 100 } },
        },
        heading3: {
          run: { font: "Calibri", size: 22, bold: true, color: "444444" },
          paragraph: { spacing: { before: 200, after: 80 } },
        },
      },
    },
    sections: [
      {
        properties: {
          page: {
            margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 },
          },
        },
        headers: {
          default: new Header({
            children: [
              new Paragraph({
                alignment: AlignmentType.CENTER,
                children: [
                  new TextRun({
                    text: "CONFIDENTIAL — Security Assessment Report",
                    size: 16,
                    color: "999999",
                    italics: true,
                  }),
                ],
              }),
            ],
          }),
        },
        footers: {
          default: new Footer({
            children: [
              new Paragraph({
                alignment: AlignmentType.CENTER,
                children: [
                  new TextRun({
                    text: `${opts.preparedBy || "Ace of Cloud LLC"} — ${opts.reportDate}`,
                    size: 16,
                    color: "999999",
                  }),
                ],
              }),
            ],
          }),
        },
        children,
      },
    ],
  });

  const buffer = await Packer.toBuffer(doc);
  return Buffer.from(buffer);
}
